# Budlum Ecosystem Interface & Visualization

**Author:** ARENA1 (Core/R&D)
**Date:** 2026-07-16
**Status:** Canonical / Design Documentation

This document outlines the visual and functional paradigms of the Budlum ecosystem interfaces: `budlum.com` and `budlum.xyz`.

---

## 1. The Gateway: Budlum.com

`budlum.com` serves as the primary landing page and educational hub of the project.

-   **Purpose:** Marketing, high-level vision, and technical documentation (`/docs`).
-   **Onboarding:** A prominent "Open Budlum" (Budlum'u Aç) button serves as the entry point to the active network interface.

---

## 2. The Ecosystem Portal: Budlum.xyz

`budlum.xyz` is the concrete, visual manifestation of the Budlum network. It is more than a dashboard; it is a "Digital Territory" map.

### 2.1 The Budlum Grid (Territories)
The interface is represented as an infinite, grid-based "Minecraft-style" landmass.

-   **Grid Units:** Each individual square (block) represents a unique **Wallet/Account**.
-   **Applications:** A larger area (e.g., a 4x4 block cluster) represents a **dApp (Application)**.
-   **Navigation:** Users can "pan and scroll" across the grid to discover different regions of the network, providing a tangible sense of the ecosystem's scale and activity.

### 2.2 Budlum Search & Analytics (bud.scan)
Located at the top of the interface, the search bar is the "Universal Lens" into the network.

-   **Search Capability:** Supports querying Wallet Addresses, NFT CIDs, BNS Names (`.bud`), and D-Web sites.
-   **Context Mapping (`+` Button):**
    -   **Wallet Context:** Clicking the `+` button on a wallet result opens a "Context Map"—a visual graph showing the wallet's transaction history, its connections to other wallets, and interaction patterns.
    -   **Token Context (Bubble Maps):** Clicking the `+` button on a token search result displays a "Bubble Map"—a visualization of the token's distribution, large holders, and supply movement patterns.

---

## 3. D-Web Integration & Browser Utility

The `budlum.xyz` interface incorporates browser-like functionality for the Decentralized Web.

-   **Name Resolution:** The search bar resolves `.bud` domains using the B.U.D. Gateway logic.
-   **Site Rendering:** Content linked to BNS names (stored on B.U.D.) can be rendered directly within the portal or via a dedicated Budlum-specific browser, ensuring a seamless D-Web experience without relying on traditional DNS.

---

## 4. Interaction Workflow

1.  **Discovery:** User explores the Grid to find an app or wallet.
2.  **Context:** User uses Search + Context Map to verify the "history and health" of a participant.
3.  **Action:** User launches the app (linked to B.U.D. Manifest) or resolves a profile.

**Budlum is not just a ledger; it is a visible, navigable digital world.**
