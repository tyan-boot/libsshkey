use crate::error::Error;

pub(crate) fn to_asn1_vec(origin: Vec<u8>) -> Result<Vec<u8>, Error> {
    let first = *origin.first().unwrap();
    if (first & 0b1000_0000) != 0 {
        let mut fixed = Vec::with_capacity(origin.len() + 1);
        fixed.push(0);
        fixed.extend(origin);

        Ok(fixed)
    } else {
        Ok(origin)
    }
}
