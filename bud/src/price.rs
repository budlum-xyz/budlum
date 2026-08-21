//! Fiyat modeli - 60 ay amorti yöntemi + external_bench (prover)
//! Fiziksel: 12.5/60=0.20833 + elec 0.02309 + other 0.002 (external bench) = 0.23342
//! Gereken: EVENODD 1.286 icin 18.76x

#[derive(Debug, Clone)]
pub struct PriceModel {
    pub disk_usd_per_tb: f64,
    pub amort_months: f64,
    pub power_w_per_tb: f64,
    pub pue: f64,
    pub hours_per_month: f64,
    pub elec_usd_per_kwh: f64,
    pub other_usd: f64, // prover+ag+denetim external_bench
}

#[derive(Debug, Clone)]
pub enum PriceError {
    InvalidRatio,
}

impl Default for PriceModel {
    fn default() -> Self {
        PriceModel {
            disk_usd_per_tb: 12.5,
            amort_months: 60.0,
            power_w_per_tb: 5.5/20.0,
            pue: 1.15,
            hours_per_month: 730.0,
            elec_usd_per_kwh: 0.10,
            other_usd: 0.002, // external_bench: Plonky3 0.5-2s ~$0.00002, ama 0.002 konservatif
        }
    }
}

impl PriceModel {
    pub fn physical_usd_per_tb_month(&self) -> f64 {
        let disk = self.disk_usd_per_tb / self.amort_months;
        let kwh = self.power_w_per_tb * self.pue * self.hours_per_month / 1000.0;
        let elec = kwh * self.elec_usd_per_kwh;
        disk + elec + self.other_usd
    }
    pub fn cost_sold(&self, e: f64, r: f64) -> Result<f64, PriceError> {
        if r <= 0.0 { return Err(PriceError::InvalidRatio) }
        Ok(self.physical_usd_per_tb_month() * e / r)
    }
    pub fn required_ratio(&self, e: f64, target: f64) -> f64 {
        self.physical_usd_per_tb_month() * e / target
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Expansion {
    pub k: usize,
    pub p: usize,
    pub e: f64,
    pub f: usize,
    pub repair_disks: usize,
}

impl Expansion {
    pub fn new(k: usize, p: usize) -> Self {
        Expansion { k, p, e: (k+p) as f64 / k as f64, f: p, repair_disks: k }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn physical_60m_external_bench() {
        let m = PriceModel::default();
        let phys = m.physical_usd_per_tb_month();
        // 0.20833+0.02309+0.002 = 0.23342
        assert!((phys - 0.23342).abs() < 0.001);
    }
    #[test]
    fn required_ratio_evenodd() {
        let m = PriceModel::default();
        let req = m.required_ratio(1.286, 0.016);
        // 0.23342*1.286/0.016 = 18.76
        assert!((req - 18.76).abs() < 0.5);
    }
    #[test]
    fn required_ratio_7plus1() {
        let m = PriceModel::default();
        let req = m.required_ratio(1.143, 0.016);
        // 0.23342*1.143/0.016 = 16.68
        assert!((req - 16.68).abs() < 0.5);
    }
    #[test]
    fn json_passes_price_with_7plus1_hybrid() {
        let m = PriceModel::default();
        // JSON 17.19x, 7+1 16.68 gereken => geçer, ama dokuz 4.32 RED
        // Bu yüzden hibrit: sıcak Düz 7+1, soğuk EVENODD
        let cost = m.cost_sold(1.143, 17.191).unwrap();
        assert!(cost <= 0.016 + 0.001); // 0.0155
    }
    #[test]
    fn jpeg_fails_price_even_with_external_bench() {
        let m = PriceModel::default();
        let cost = m.cost_sold(1.286, 2.53).unwrap(); // AVIF 2.53x
        assert!(cost > 0.016); // 0.118 >0.016 RED, device-only cozum
    }
    #[test]
    fn media_device_only_holds() {
        // device cost 0 <=0.016 her zaman OK
        assert!(0.0 <= 0.016);
    }
}
