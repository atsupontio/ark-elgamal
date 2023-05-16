#[cfg(feature = "r1cs")]
pub mod constraints;

use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_crypto_primitives::Error;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{fields::PrimeField, UniformRand};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;

pub struct ElGamal<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}

pub struct Parameters<C: ProjectiveCurve> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as ProjectiveCurve>::Affine;

pub struct SecretKey<C: ProjectiveCurve>(pub C::ScalarField);

pub struct Randomness<C: ProjectiveCurve>(pub C::ScalarField);

impl<C: ProjectiveCurve> UniformRand for Randomness<C> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(<C as ProjectiveCurve>::ScalarField::rand(rng))
    }
}

pub type Plaintext<C> = <C as ProjectiveCurve>::Affine;

pub type Ciphertext<C> = (
    <C as ProjectiveCurve>::Affine,
    <C as ProjectiveCurve>::Affine,
);

impl<C: ProjectiveCurve> AsymmetricEncryptionScheme for ElGamal<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Randomness = Randomness<C>;
    type Plaintext = Plaintext<C>;
    type Ciphertext = Ciphertext<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        // get a random generator
        let generator = C::rand(rng).into();

        Ok(Parameters { generator })
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        // get a random element from the scalar field
        let secret_key: <C as ProjectiveCurve>::ScalarField = C::ScalarField::rand(rng);

        // compute secret_key*generator to derive the public key
        let public_key = pp.generator.mul(secret_key).into();

        Ok((public_key, SecretKey(secret_key)))
    }

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, Error> {
        // compute s = r*pk
        let s = pk.mul(r.0).into();

        // compute c1 = r*generator
        let c1 = pp.generator.mul(r.0).into();

        // compute c2 = m + s
        let c2 = *message + s;

        Ok((c1, c2))
    }

    fn decrypt(
        _pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Error> {
        let c1: <C as ProjectiveCurve>::Affine = ciphertext.0;
        let c2: <C as ProjectiveCurve>::Affine = ciphertext.1;

        // compute s = secret_key * c1
        let s = c1.mul(sk.0);
        let s_inv = -s;

        // compute message = c2 - s
        let m = c2 + s_inv.into_affine();

        Ok(m)
    }
}

use std::fmt::Write;
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

#[cfg(test)]
mod test {

    use std::assert_eq;
    use std::println;

    use ark_ff::BigInteger;
    use ark_std::One;
    use ark_std::{test_rng, UniformRand, Zero};
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ed_on_bls12_381::EdwardsAffine;
    use ark_ed_on_bls12_381::Fr as ScalarField;
    use ark_ed_on_bls12_381::Fq;
    // use ark_bls12_381::{Fq, FqParameters};
    // use ark_crypto_primitives::encryption::elgamal::{ElGamal, Randomness};
    use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
    use ark_ff::{PrimeField, Field, Fp384};
    use ark_ec::ProjectiveCurve;
    use ark_ec::AffineCurve;
    use base58::ToBase58;



    #[test]
    fn test_elgamal_encryption() {
        let mut rng = &mut test_rng();

        let id = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y";
        // decode id by base58 decoder
        let mut new_id = base58::FromBase58::from_base58(id).unwrap();
        // Adjusting to a point over a finite field
        let mut id_acc = Vec::new();

        // 
        let new_id2 = new_id.to_base58();
        
        // Adjusting to a point over a finite field
        while Fq::from_random_bytes(&new_id).is_none() {
            id_acc.push(new_id.pop().unwrap());
        }
        // Adjusting to a point over an elliptic curve
        while EdwardsAffine::get_point_from_x(Fq::from_random_bytes(&new_id).unwrap(), true).is_none() {
            id_acc.push(new_id.pop().unwrap());
        }
        println!("new_id: {:?}, new_id_len:{:?}", new_id2, id_acc.len());

        // Id on a finite field
        let id_scalar = Fq::from_random_bytes(&new_id).unwrap();

        // Convert back from a point on a finite field to the original data
        let mut a = id_scalar.into_repr().to_bytes_le();
        a.retain(|&x| x != 0);
        assert_eq!(a, new_id);

        // Convert a field element to an affine point on an elliptic curve
        let e_aff = EdwardsAffine::get_point_from_x(id_scalar, true).unwrap();
        // convert from affine to projective
        let e_pro = e_aff.into_projective();


        let new_e = e_pro.clone();
        let count = 0;
        // let k_inv = ScalarField::one();


        // while !new_e.into_affine().is_in_correct_subgroup_assuming_on_curve() {
        //     let k = ScalarField::rand(&mut rng);

        //     assert!(!k.is_zero());
        //     new_e = e_pro.mul(k.into_repr());
            
        //     k_inv = k.inverse().unwrap();

        //     assert_eq!(new_e.mul(k_inv.into_repr()), e_pro);
        //     count+=1;
        // }

        // assert_eq!(new_e, e_pro.mul(k_inv_acc[5].inverse().unwrap().into_repr()));
        // assert_eq!(new_e.mul(k_inv_acc[5].into_repr()), e_pro);
        
        // println!("k_inv_acc: {:?}", k_inv_acc.len());

        println!("count: {:?}", count);
        // check whether the point is on curve
        assert!(new_e.into_affine().is_on_curve());
        // TODO: check whether the point is on correct subgroup
        // assert!(new_e.into_affine().is_in_correct_subgroup_assuming_on_curve());
        

        // setup and key generation
        let parameters = crate::ElGamal::<JubJub>::setup(rng).unwrap();
        let (pk, sk) = crate::ElGamal::<JubJub>::keygen(&parameters, rng).unwrap();

        // let msg = JubJub::rand(rng).into();
        // println!("message: {:?}", msg);
        // get a random msg and encryption randomness
        let msg = new_e.into_affine();
        println!("message: {:?}", msg);
        let r = crate::Randomness::rand(rng);

        // encrypt and decrypt the message
        let cipher = crate::ElGamal::<JubJub>::encrypt(&parameters, &pk, &msg, &r).unwrap();
        let check_msg = crate::ElGamal::<JubJub>::decrypt(&parameters, &sk, &cipher).unwrap();
        assert_eq!(msg, check_msg);


        // x-coordinate (plaintext)
        let mut a = msg.x.into_repr().to_bytes_le();

        // push accumulated bytes
        while let Some(val) = id_acc.pop() {
            a.push(val);
        }

        println!("hirabun: {:?}", a);
        // when "a" is created, 0 padding is added
        // remove 0 padding
        a.retain(|&x| x != 0);
        let ans = a.to_base58();
        println!("ans: {:?}", ans);
        

    }
}
fn main(){}

