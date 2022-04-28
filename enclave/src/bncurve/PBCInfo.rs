pub struct PBCInfo {
  context: u8, // which slot in the gluelib context table
  name: *const str,
  text: *const str,
  g1_size: usize,
  g2_size: usize,
  pairing_size: usize,
  field_size: usize,
  order: *const str,
  g1: *const str,
  g2: *const str,
}