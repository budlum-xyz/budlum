//! Offline i18n and accessibility seams for the AI inference layer.
//!
//! WIRING: unwired - this seam ships ahead of its caller on purpose. It is
//! phase 4 of the FSF adaptation plan, and the wallet/UI surface that will
//! call `translate` is not in this PR. It is here now so the data shapes and
//! their commitments are reviewable before anything depends on them. Delete
//! this marker in the change that wires it; the gate refuses the marker once
//! something calls the module, so it cannot rot into a permanent excuse.
//!
//! This is deliberately a *seam*, not a bundled translation or speech model.
//! Budlum records deterministic provider identities, locale tags, localized text
//! commitments and transcript provenance while keeping actual translation/STT
//! engines outside consensus and local to the operator or UI. The shape is
//! inspired by offline i18n/accessibility design briefs, but the implementation
//! is Budlum-native and imports no upstream project source.

use std::collections::BTreeMap;
use std::fmt;

use crate::core::hash::hash_fields_bytes;

const LOCAL_I18N_DOMAIN: &[u8] = b"BDLM-AI-LOCAL-I18N-v1";
const LOCAL_TRANSCRIPT_DOMAIN: &[u8] = b"BDLM-AI-ACCESSIBILITY-TRANSCRIPT-v1";

/// Error returned by the local i18n/accessibility seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum I18nError {
    /// The locale tag is outside Budlum's deterministic BCP-47 subset.
    InvalidLocaleTag(String),
    /// The provider id must be a local deterministic identifier, not a URL.
    InvalidProviderId(String),
    /// Translation keys are stable identifiers, not free-form text.
    InvalidTranslationKey(String),
    /// Empty localized text/transcripts are refused so callers fail closed.
    EmptyText,
    /// No exact local entry exists for `(key, locale, accessibility mode)`.
    MissingTranslation {
        key: String,
        locale: LocaleTag,
        mode: AccessibilityMode,
    },
}

impl fmt::Display for I18nError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLocaleTag(tag) => write!(f, "invalid locale tag: {tag}"),
            Self::InvalidProviderId(id) => write!(f, "invalid local provider id: {id}"),
            Self::InvalidTranslationKey(key) => write!(f, "invalid translation key: {key}"),
            Self::EmptyText => f.write_str("localized text/transcript must not be empty"),
            Self::MissingTranslation { key, locale, mode } => write!(
                f,
                "missing local translation for key={key}, locale={locale}, mode={mode:?}"
            ),
        }
    }
}

impl std::error::Error for I18nError {}

/// Deterministic subset of BCP-47 locale tags used at Budlum boundaries.
///
/// A full BCP-47 registry lookup is intentionally *not* performed here because
/// that would make consensus and test fixtures depend on mutable external data.
/// The subset accepts common tags such as `tr`, `en-US`, `az-Latn-AZ` and
/// `sr-Cyrl`; it canonicalizes case and rejects underscores, empty subtags and
/// non-ASCII input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocaleTag(String);

impl LocaleTag {
    /// Parse and canonicalize a locale tag.
    ///
    /// # Errors
    ///
    /// Returns [`I18nError::InvalidLocaleTag`] when the tag is empty, contains
    /// separators other than `-`, contains non-ASCII alphanumerics, has empty
    /// subtags, or uses a primary language subtag outside Budlum's deterministic
    /// subset.
    pub fn new(tag: &str) -> Result<Self, I18nError> {
        if tag.is_empty() || tag.len() > 35 || tag.contains('_') {
            return Err(I18nError::InvalidLocaleTag(tag.to_string()));
        }

        let mut out = Vec::new();
        for (idx, part) in tag.split('-').enumerate() {
            if part.is_empty() || part.len() > 8 || !part.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                return Err(I18nError::InvalidLocaleTag(tag.to_string()));
            }

            if idx == 0 {
                if !(2..=3).contains(&part.len()) || !part.bytes().all(|b| b.is_ascii_alphabetic())
                {
                    return Err(I18nError::InvalidLocaleTag(tag.to_string()));
                }
                out.push(part.to_ascii_lowercase());
            } else if part.len() == 4 && part.bytes().all(|b| b.is_ascii_alphabetic()) {
                // Built by position rather than `chars.next().expect(..)`.
                // The length check above does guarantee a first character, but
                // this crate denies `clippy::expect_used`: a proof that lives
                // in a neighbouring `if` is exactly the kind that stops being
                // true when someone edits the condition.
                let mut title = String::with_capacity(part.len());
                for (index, ch) in part.chars().enumerate() {
                    if index == 0 {
                        title.push(ch.to_ascii_uppercase());
                    } else {
                        title.push(ch.to_ascii_lowercase());
                    }
                }
                out.push(title);
            } else if part.len() == 2 && part.bytes().all(|b| b.is_ascii_alphabetic()) {
                out.push(part.to_ascii_uppercase());
            } else {
                out.push(part.to_ascii_lowercase());
            }
        }

        Ok(Self(out.join("-")))
    }

    /// Canonical locale tag string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LocaleTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// How localized text should be shaped for accessibility surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AccessibilityMode {
    /// Normal UI/documentation string.
    UiText,
    /// Plain text with decorative punctuation/markup removed by the provider.
    PlainText,
    /// Text intended for screen readers.
    ScreenReader,
    /// Captions/subtitles for audio or video surfaces.
    Captions,
    /// Transcript text produced by a local speech-to-text adapter.
    Transcript,
}

impl AccessibilityMode {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::UiText => b"ui-text",
            Self::PlainText => b"plain-text",
            Self::ScreenReader => b"screen-reader",
            Self::Captions => b"captions",
            Self::Transcript => b"transcript",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LocalizedKey {
    key: String,
    locale: LocaleTag,
    mode: AccessibilityMode,
}

/// A deterministic localized string returned by a local provider/catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalizedText {
    /// Local provider/catalog id. This must not be a URL.
    pub provider_id: String,
    /// Stable translation key, for example `wallet.send.confirm`.
    pub key: String,
    /// Canonical locale tag.
    pub locale: LocaleTag,
    /// Accessibility shape used for this string.
    pub mode: AccessibilityMode,
    /// The localized text.
    pub text: String,
    /// Domain-separated commitment binding provider, key, locale, mode and text.
    pub commitment: [u8; 32],
}

impl LocalizedText {
    /// Recompute the commitment from the visible fields.
    #[must_use]
    pub fn calculate_commitment(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            LOCAL_I18N_DOMAIN,
            self.provider_id.as_bytes(),
            self.key.as_bytes(),
            self.locale.as_str().as_bytes(),
            self.mode.tag(),
            self.text.as_bytes(),
        ])
    }
}

/// Small in-memory catalog for tests, fixtures and offline UI/doc adapters.
///
/// The catalog does exact lookups only: no network fallback, no implicit source
/// language fallback, and no best-effort machine translation. A missing entry is
/// an error so callers cannot silently ship a mixed-language or inaccessible UI.
pub struct OfflineLocalizationCatalog {
    provider_id: String,
    entries: BTreeMap<LocalizedKey, String>,
}

impl OfflineLocalizationCatalog {
    /// Create an empty local catalog.
    ///
    /// # Errors
    ///
    /// Returns [`I18nError::InvalidProviderId`] if `provider_id` looks like a
    /// URL/path or contains non-deterministic whitespace/control characters.
    pub fn new(provider_id: &str) -> Result<Self, I18nError> {
        validate_provider_id(provider_id)?;
        Ok(Self {
            provider_id: provider_id.to_string(),
            entries: BTreeMap::new(),
        })
    }

    /// Provider/catalog id used in returned commitments.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    /// Insert or replace a localized fixture.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid keys or empty text.
    pub fn insert(
        &mut self,
        key: &str,
        locale: LocaleTag,
        mode: AccessibilityMode,
        text: &str,
    ) -> Result<(), I18nError> {
        validate_translation_key(key)?;
        if text.is_empty() {
            return Err(I18nError::EmptyText);
        }
        self.entries.insert(
            LocalizedKey {
                key: key.to_string(),
                locale,
                mode,
            },
            text.to_string(),
        );
        Ok(())
    }

    /// Return an exact local translation.
    ///
    /// # Errors
    ///
    /// Returns [`I18nError::MissingTranslation`] when the exact
    /// `(key, locale, mode)` tuple is absent.
    pub fn translate(
        &self,
        key: &str,
        locale: &LocaleTag,
        mode: AccessibilityMode,
    ) -> Result<LocalizedText, I18nError> {
        validate_translation_key(key)?;
        let lookup = LocalizedKey {
            key: key.to_string(),
            locale: locale.clone(),
            mode,
        };
        let text = self
            .entries
            .get(&lookup)
            .ok_or_else(|| I18nError::MissingTranslation {
                key: key.to_string(),
                locale: locale.clone(),
                mode,
            })?;
        let mut localized = LocalizedText {
            provider_id: self.provider_id.clone(),
            key: key.to_string(),
            locale: locale.clone(),
            mode,
            text: text.clone(),
            commitment: [0; 32],
        };
        localized.commitment = localized.calculate_commitment();
        Ok(localized)
    }
}

/// Provenance for a transcript produced by a local speech-to-text adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessibilityTranscript {
    /// Commitment/hash of the source audio object. The seam stores provenance,
    /// not raw audio or nondeterministic model state.
    pub audio_commitment: [u8; 32],
    /// Local STT provider id. This must not be a URL.
    pub provider_id: String,
    /// Language/locale claimed by the local adapter.
    pub locale: LocaleTag,
    /// Transcript text produced by the adapter.
    pub text: String,
    /// Domain-separated commitment binding audio, provider, locale and text.
    pub transcript_commitment: [u8; 32],
}

impl AccessibilityTranscript {
    /// Build transcript provenance for a local STT output.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider id is not local/deterministic or the
    /// transcript is empty.
    /// Convenience: exposed for the operator-side STT path. Unreached for the
    /// same reason as the rest of this module (see its WIRING note).
    pub fn from_local_stt(
        provider_id: &str,
        audio_commitment: [u8; 32],
        locale: LocaleTag,
        text: &str,
    ) -> Result<Self, I18nError> {
        validate_provider_id(provider_id)?;
        if text.is_empty() {
            return Err(I18nError::EmptyText);
        }
        let mut transcript = Self {
            audio_commitment,
            provider_id: provider_id.to_string(),
            locale,
            text: text.to_string(),
            transcript_commitment: [0; 32],
        };
        transcript.transcript_commitment = transcript.calculate_commitment();
        Ok(transcript)
    }

    /// Recompute the transcript commitment from visible provenance fields.
    #[must_use]
    pub fn calculate_commitment(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            LOCAL_TRANSCRIPT_DOMAIN,
            &self.audio_commitment,
            self.provider_id.as_bytes(),
            self.locale.as_str().as_bytes(),
            self.text.as_bytes(),
        ])
    }
}

fn validate_provider_id(provider_id: &str) -> Result<(), I18nError> {
    let valid = !provider_id.is_empty()
        && provider_id.len() <= 64
        && !provider_id.contains("://")
        && !provider_id.contains('/')
        && !provider_id.contains('\\')
        && provider_id
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'?' && b != b'#');
    if valid {
        Ok(())
    } else {
        Err(I18nError::InvalidProviderId(provider_id.to_string()))
    }
}

fn validate_translation_key(key: &str) -> Result<(), I18nError> {
    let valid = !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(I18nError::InvalidTranslationKey(key.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_tags_are_canonicalized_without_registry_lookup() {
        assert_eq!(LocaleTag::new("TR").expect("locale").as_str(), "tr");
        assert_eq!(LocaleTag::new("en-us").expect("locale").as_str(), "en-US");
        assert_eq!(
            LocaleTag::new("az-latn-az").expect("locale").as_str(),
            "az-Latn-AZ"
        );
        assert!(LocaleTag::new("en_US").is_err());
        assert!(LocaleTag::new("http://example").is_err());
    }

    #[test]
    fn catalog_is_exact_and_local_only() {
        let tr = LocaleTag::new("fr").expect("locale");
        let mut catalog = OfflineLocalizationCatalog::new("budlum-fixture-v1").expect("catalog");
        catalog
            .insert(
                "wallet.send.confirm",
                tr.clone(),
                AccessibilityMode::ScreenReader,
                "Confirmer l'envoi",
            )
            .expect("insert");

        let localized = catalog
            .translate("wallet.send.confirm", &tr, AccessibilityMode::ScreenReader)
            .expect("translation");
        assert_eq!(localized.provider_id, "budlum-fixture-v1");
        assert_eq!(localized.locale, tr);
        assert_eq!(localized.text, "Confirmer l'envoi");
        assert_eq!(localized.commitment, localized.calculate_commitment());

        assert!(matches!(
            catalog.translate(
                "wallet.send.confirm",
                &localized.locale,
                AccessibilityMode::UiText
            ),
            Err(I18nError::MissingTranslation { .. })
        ));
        assert!(OfflineLocalizationCatalog::new("https://hosted.example/api").is_err());
    }

    #[test]
    fn localized_commitment_binds_key_locale_mode_and_text() {
        let tr = LocaleTag::new("fr").expect("locale");
        let en = LocaleTag::new("en-US").expect("locale");
        let mut catalog = OfflineLocalizationCatalog::new("budlum-fixture-v1").expect("catalog");
        catalog
            .insert(
                "a11y.caption",
                tr.clone(),
                AccessibilityMode::Captions,
                "Pret a l'emploi",
            )
            .expect("insert");
        catalog
            .insert(
                "a11y.caption",
                en.clone(),
                AccessibilityMode::Captions,
                "Ready",
            )
            .expect("insert");
        catalog
            .insert(
                "a11y.caption",
                tr.clone(),
                AccessibilityMode::PlainText,
                "Pret a l'emploi",
            )
            .expect("insert");
        catalog
            .insert(
                "a11y.other",
                tr.clone(),
                AccessibilityMode::Captions,
                "Pret a l'emploi",
            )
            .expect("insert");

        let base = catalog
            .translate("a11y.caption", &tr, AccessibilityMode::Captions)
            .expect("translation");
        assert_ne!(
            base.commitment,
            catalog
                .translate("a11y.caption", &en, AccessibilityMode::Captions)
                .expect("translation")
                .commitment
        );
        assert_ne!(
            base.commitment,
            catalog
                .translate("a11y.caption", &tr, AccessibilityMode::PlainText)
                .expect("translation")
                .commitment
        );
        assert_ne!(
            base.commitment,
            catalog
                .translate("a11y.other", &tr, AccessibilityMode::Captions)
                .expect("translation")
                .commitment
        );
    }

    #[test]
    fn transcript_commitment_binds_audio_provider_locale_and_text() {
        let locale = LocaleTag::new("tr").expect("locale");
        let base = AccessibilityTranscript::from_local_stt(
            "local-stt-fixture-v1",
            [7; 32],
            locale.clone(),
            "Merhaba Budlum",
        )
        .expect("transcript");
        assert_eq!(base.transcript_commitment, base.calculate_commitment());

        assert_ne!(
            base.transcript_commitment,
            AccessibilityTranscript::from_local_stt(
                "local-stt-fixture-v2",
                [7; 32],
                locale.clone(),
                "Merhaba Budlum",
            )
            .expect("transcript")
            .transcript_commitment
        );
        assert_ne!(
            base.transcript_commitment,
            AccessibilityTranscript::from_local_stt(
                "local-stt-fixture-v1",
                [8; 32],
                locale.clone(),
                "Merhaba Budlum",
            )
            .expect("transcript")
            .transcript_commitment
        );
        assert_ne!(
            base.transcript_commitment,
            AccessibilityTranscript::from_local_stt(
                "local-stt-fixture-v1",
                [7; 32],
                LocaleTag::new("en-US").expect("locale"),
                "Merhaba Budlum",
            )
            .expect("transcript")
            .transcript_commitment
        );
        assert_ne!(
            base.transcript_commitment,
            AccessibilityTranscript::from_local_stt(
                "local-stt-fixture-v1",
                [7; 32],
                locale,
                "Merhaba",
            )
            .expect("transcript")
            .transcript_commitment
        );
        assert!(AccessibilityTranscript::from_local_stt(
            "https://hosted.example/stt",
            [7; 32],
            LocaleTag::new("tr").expect("locale"),
            "Merhaba",
        )
        .is_err());
    }
}
