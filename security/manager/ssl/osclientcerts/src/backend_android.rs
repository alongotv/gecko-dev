use pkcs11_bindings::*;
use rsclientcerts::error::{Error, ErrorType};
use rsclientcerts::manager::{ClientCertsBackend, CryptokiObject, Sign, SlotType};
use rsclientcerts::util::*;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::ffi::{c_void, CStr, CString};
use std::ops::Deref;
use std::slice;

// This is the interface to the JVM that we'll call the majority of our
// methods on.
use jni::{JavaVM, JNIEnv, AttachGuard};
// This is just a pointer. We'll be returning it from our function. We
// can't return one of the objects with lifetime information because the
// lifetime checker won't let us.
use log::LevelFilter;
use android_logger::Config;
// These objects are mappings to objects provided by JNI
use jni::sys::{jobject, jobjectArray, jbyteArray, jarray};
// These objects are what you should use as arguments to your native
// function. They carry extra lifetime information to prevent them escaping
// this context and getting used after being GC'd.
use jni::objects::{GlobalRef, JValue, JClass, JObject, JString, JMethodID};

static mut JVM: Option<JavaVM> = None;
static mut CLASS_LOADER: Option<GlobalRef> = None;
static mut CLASS_LOADER_FIND_CLASS_METHOD_ID: Option<JMethodID> = None;


pub struct Backend {}

pub struct Cert {
    cert: CertObject,
    class: Vec<u8>,
    token: Vec<u8>,
    id: Vec<u8>,
    label: Vec<u8>,
    value: Vec<u8>,
    issuer: Vec<u8>,
    serial_number: Vec<u8>,
    subject: Vec<u8>,
}

pub struct Key {
    key: KeyObject,
    class: Vec<u8>,
    token: Vec<u8>,
    id: Vec<u8>,
    private: Vec<u8>,
    key_type: Vec<u8>,
    modulus: Option<Vec<u8>>,
    key_type_enum: KeyType,
    ec_params: Option<Vec<u8>>,
}

struct CertObject(jobject);

impl CertObject {
    fn new(obj: jobject) -> CertObject {
        CertObject(obj)
    }
}


struct KeyObject(GlobalRef);

impl KeyObject {
    fn new(obj: GlobalRef) -> KeyObject {
        KeyObject(obj)
    }
}

impl Cert {
    // Accepts a valid java.security.cert.X509Certificate jobject
    fn new(cert_jobject: jobject) -> Result<Cert, Error> {
        let env = unsafe {
            JVM.as_mut().unwrap()
                .attach_current_thread()
                .expect("Unable to attach to current thread")
        };

        // A hardcoded label. There is no self-implemented user interface for picking
        // a certificate from the KeyChain in Android, so it will never be presented to the user.
        let label = "placeholder_label".to_owned().into_bytes();
        // Get a X509Certificate object
        let cert_object: JObject = unsafe { JObject::from_raw(cert_jobject) };
        // Get certificate DER object (Java's byte array under the hood)
        let encoded_certificate: jbyteArray = env.call_method(cert_object, "getEncoded", "()[B", &[]).unwrap().l().unwrap().into_raw();
        // Convert certificate DER object to Vec<u8>
        let value: Vec<u8> = env.convert_byte_array(encoded_certificate).unwrap();
        let id = Sha256::digest(&value).to_vec();
        let (serial_number, issuer, subject) = read_encoded_certificate_identifiers(&value)?;

        Ok(Cert {
            cert: CertObject::new(*cert_object),
            class: serialize_uint(CKO_CERTIFICATE)?,
            token: serialize_uint(CK_TRUE)?,
            id: id,
            label: label,
            value: value,
            issuer: issuer,
            serial_number: serial_number,
            subject: subject,
        })
    }

    fn class(&self) -> &[u8] {
        &self.class
    }

    fn token(&self) -> &[u8] {
        &self.token
    }

    fn id(&self) -> &[u8] {
        &self.id
    }

    fn label(&self) -> &[u8] {
        &self.label
    }

    fn value(&self) -> &[u8] {
        &self.value
    }

    fn issuer(&self) -> &[u8] {
        &self.issuer
    }

    fn serial_number(&self) -> &[u8] {
        &self.serial_number
    }

    fn subject(&self) -> &[u8] {
        &self.subject
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug)]
pub enum KeyType {
    EC,
    RSA,
}

#[allow(clippy::upper_case_acronyms)]
enum SignParams<'a> {
    EC(JString<'a>, &'a [u8]),
    RSA(JString<'a>, &'a [u8]),
}

impl<'a> SignParams<'a> {
    fn new(
        key_type: KeyType,
        data: &'a [u8],
        params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<SignParams<'a>, Error> {
        match key_type {
            KeyType::EC => SignParams::new_ec_params(data),
            KeyType::RSA => SignParams::new_rsa_params(params, data),
        }
    }

    fn get_algorithm(&self) -> &JString {
        match self {
            SignParams::EC(algorithm, _) => algorithm,
            SignParams::RSA(algorithm, _) => algorithm,
        }
    }

    fn get_data_to_sign(&self) -> &'a [u8] {
        match self {
            SignParams::EC(_, data_to_sign) => data_to_sign,
            SignParams::RSA(_, data_to_sign) => data_to_sign,
        }
    }

    fn new_ec_params(data: &'a [u8]) -> Result<SignParams<'a>, Error> {
        let env = unsafe {
            JVM.as_mut().unwrap()
                .attach_current_thread()
                .expect("Unable to attach to current thread")
        };

        let algorithm_id = match data.len() {
            20 => "SHA1withECDSA",
            32 => "SHA256withECDSA",
            48 => "SHA384withECDSA",
            64 => "SHA512withECDSA",
            _ => {
                return Err(error_here!(ErrorType::UnsupportedInput));
            }
        };
        let algorithm: JString = env
            .new_string(&algorithm_id)
            .expect("Unable to create a java String!")
            .into();

        // Ok(SignParams::EC(algorithm, data))
        // Not tested!
        // We do not support EC algorithms in Android just yet
        Err(error_here!(ErrorType::UnsupportedInput))
    }

    fn new_rsa_params(
        params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
        data: &'a [u8],
    ) -> Result<SignParams<'a>, Error> {
        let env = unsafe {
            JVM.as_mut().unwrap()
                .attach_current_thread()
                .expect("Unable to attach to current thread")
        };

        if data.len() == 36 {
            error!("TLS 1.0 is no longer supported");
            return Err(error_here!(ErrorType::UnsupportedInput));
        }

        if let Some(pss_params) = params {
            let algorithm: JString = {
                let algorithm_id = match pss_params.hashAlg {
                    // All of these algorithms include hashing during the signature process
                    // However, the "data" parameter seems to be already hashed
                    CKM_SHA_1 => "SHA1withRSA/PSS",
                    CKM_SHA256 => "SHA256withRSA/PSS",
                    CKM_SHA384 => "SHA384withRSA/PSS",
                    CKM_SHA512 => "SHA512withRSA/PSS",
                    _ => {
                        return Err(error_here!(ErrorType::UnsupportedInput));
                    }
                };
                let algorithm: JString = env
                    .new_string(&algorithm_id)
                    .expect("Unable to create a java String!")
                    .into();
                algorithm
            };
            // The "data" parameter should not be hashed for this to actually work:
            // there is no algorithm for signing hashed data using RSA-PSS in Android
            return Ok(SignParams::RSA(algorithm, data));
        }

        // Select an algorithm for further encoding
        let (digest_oid, _) = read_digest_info(data)?;
        let algorithm_id = match digest_oid {
            OID_BYTES_SHA_256 => "SHA-256",
            OID_BYTES_SHA_384 => "SHA-384",
            OID_BYTES_SHA_512 => "SHA-512",
            OID_BYTES_SHA_1 => "SHA-1",
            _ => return Err(error_here!(ErrorType::UnsupportedInput)),
        };

        let algorithm: JString = env
            .new_string(&algorithm_id)
            .expect("Unable to create a java String!")
            .into();
        // We pass DigestInfo with selected algorithm to JNI to handle the hash encoding in Java
        Ok(SignParams::RSA(algorithm, data))
    }
}

impl Key {
    fn new(key_jobject: jobject, id: Vec<u8>) -> Result<Key, Error> {
        let mut modulus: Option<Vec<u8>> = None;
        let mut key_global_ref: Option<GlobalRef> = None;
        unsafe {
            let env = JVM.as_mut().unwrap()
                .attach_current_thread()
                .expect("Unable to attach to current thread (Key::new)");
            // Get PrivateKey object
            let key_object = JObject::from_raw(key_jobject);
            // Make a global reference to PrivateKey: necessary so that it does not get deallocated
            // until the actual signature happens
            key_global_ref = Some(env.new_global_ref(key_object).unwrap());
            // Get PrivateKey's modulus
            let modulus_object: JObject = env.call_method(key_object, "getModulus", "()Ljava/math/BigInteger;", &[]).unwrap().l().unwrap();
            let modulus_byte_array: jbyteArray = env.call_method(modulus_object, "toByteArray", "()[B", &[]).unwrap().l().unwrap().into_raw();
            modulus = Some(env.convert_byte_array(modulus_byte_array).unwrap());
        }


        Ok(Key {
            key: KeyObject(key_global_ref.unwrap()),
            class: serialize_uint(CKO_PRIVATE_KEY)?,
            token: serialize_uint(CK_TRUE)?,
            id: id,
            private: serialize_uint(CK_TRUE)?,
            key_type: serialize_uint(CKK_RSA)?,
            key_type_enum: KeyType::RSA,
            modulus,
            ec_params: None,
        })
    }
    fn modulus(&self) -> Option<&[u8]> {
        match &self.modulus {
            Some(modulus) => Some(modulus.as_slice()),
            None => None,
        }
    }

    fn class(&self) -> &[u8] {
        &self.class
    }

    fn token(&self) -> &[u8] {
        &self.token
    }

    fn id(&self) -> &[u8] {
        &self.id
    }

    fn private(&self) -> &[u8] {
        &self.private
    }

    fn key_type(&self) -> &[u8] {
        &self.key_type
    }

    fn ec_params(&self) -> Option<&[u8]> {
        match &self.ec_params {
            Some(ec_params) => Some(ec_params.as_slice()),
            None => None,
        }
    }
}


impl ClientCertsBackend for Backend {
    type Cert = Cert;
    type Key = Key;

    // For debugging purposes it is assumed that we receive one PrivateKey,
    // and a certificate chain which is associated with this PrivateKey.
    // Later, this could be modified to accept multiple cert chains with their private keys:
    // would be useful when the cert chain and a key are not obtained from
    // Keychain.choosePrivateKeyAlias callback
    fn find_objects(&self) -> Result<(Vec<Cert>, Vec<Key>), Error> {
        let mut certs: Vec<Cert> = Vec::new();
        let mut keys: Vec<Key> = Vec::new();

        unsafe {
            let env = JVM.as_mut().unwrap()
                .attach_current_thread()
                .expect("Unable to attach to current thread (find_objects)");
            let clientCertificatesClass: JClass = findClass("org/mozilla/gecko/ClientCertificates");
            let pair_certs_keys = env.call_static_method(clientCertificatesClass, "getCertificatesWithPrivateKeys",
                                                         "()Landroid/util/Pair;", &[]).unwrap().l().unwrap();

            let certs_jobjectarray: jobjectArray = env.get_field(pair_certs_keys, "first", "Ljava/lang/Object;").unwrap().l().unwrap().into_raw();
            let certs_jobjectarray_length = env.get_array_length(certs_jobjectarray).unwrap();
            let keys_jobjectarray: jobjectArray = env.get_field(pair_certs_keys, "second", "Ljava/lang/Object;").unwrap().l().unwrap().into_raw();
            let keys_jobjectarray_length = env.get_array_length(keys_jobjectarray).unwrap();

            if (certs_jobjectarray_length == 0) || (keys_jobjectarray_length == 0) {
                // No certificates/keys were provided by the user
                return Ok((certs, keys));
            }
            for cert_index in 0..(certs_jobjectarray_length) {
                let cert_jobject = env.get_object_array_element(certs_jobjectarray, cert_index).unwrap();
                certs.push(Cert::new(cert_jobject.into_raw()).unwrap())
            }

            let key_jobject = env.get_object_array_element(keys_jobjectarray, 0).unwrap();
            // For each certificate in chain add a private key
            for key_index in 0..(certs_jobjectarray_length) {
                let cert_id: Vec<u8> = certs.get(0).unwrap().id.clone().to_owned();
                keys.push(Key::new(key_jobject.into_raw(), cert_id).unwrap());
            }
        }
        info!("find_objects certs {}", certs.len());
        info!("find_objects keys {}", keys.len());

        Ok((certs, keys))
    }
}


impl CryptokiObject for Key {
    fn matches(&self, slot_type: SlotType, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        // The modern/legacy slot distinction in theory enables differentiation
        // between keys that are from modules that can use modern cryptography
        // (namely EC keys and RSA-PSS signatures) and those that cannot.
        // However, the function that would enable this
        // (SecKeyIsAlgorithmSupported) causes a password dialog to appear on
        // our test machines, so this backend pretends that everything supports
        // modern crypto for now.
        if slot_type != SlotType::Modern {
            return false;
        }

        for (attr_type, attr_value) in attrs {
            let comparison = match *attr_type {
                CKA_CLASS => self.class(),
                CKA_TOKEN => self.token(),
                CKA_ID => self.id(),
                CKA_PRIVATE => self.private(),
                CKA_KEY_TYPE => self.key_type(),
                CKA_MODULUS => {
                    if let Some(modulus) = self.modulus() {
                        modulus
                    } else {
                        return false;
                    }
                }
                CKA_EC_PARAMS => {
                    if let Some(ec_params) = self.ec_params() {
                        ec_params
                    } else {
                        return false;
                    }
                }
                _ => return false,
            };
            if attr_value.as_slice() != comparison {
                return false;
            }
        }
        true
    }

    fn get_attribute(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        match attribute {
            CKA_CLASS => Some(self.class()),
            CKA_TOKEN => Some(self.token()),
            CKA_ID => Some(self.id()),
            CKA_PRIVATE => Some(self.private()),
            CKA_KEY_TYPE => Some(self.key_type()),
            CKA_MODULUS => self.modulus(),
            CKA_EC_PARAMS => self.ec_params(),
            _ => None,
        }
    }
}

impl CryptokiObject for Cert {
    fn matches(&self, slot_type: SlotType, attrs: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        if slot_type != SlotType::Modern {
            return false;
        }
        for (attr_type, attr_value) in attrs {
            let comparison = match *attr_type {
                CKA_CLASS => self.class(),
                CKA_TOKEN => self.token(),
                CKA_LABEL => self.label(),
                CKA_ID => self.id(),
                CKA_VALUE => self.value(),
                CKA_ISSUER => self.issuer(),
                CKA_SERIAL_NUMBER => self.serial_number(),
                CKA_SUBJECT => self.subject(),
                _ => return false,
            };
            if attr_value.as_slice() != comparison {
                return false;
            }
        }
        true
    }

    fn get_attribute(&self, attribute: CK_ATTRIBUTE_TYPE) -> Option<&[u8]> {
        let result = match attribute {
            CKA_CLASS => self.class(),
            CKA_TOKEN => self.token(),
            CKA_LABEL => self.label(),
            CKA_ID => self.id(),
            CKA_VALUE => self.value(),
            CKA_ISSUER => self.issuer(),
            CKA_SERIAL_NUMBER => self.serial_number(),
            CKA_SUBJECT => self.subject(),
            _ => return None,
        };
        Some(result)
    }
}

impl Sign for Key {
    fn get_signature_length(
        &mut self,
        data: &[u8],
        params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<usize, Error> {
        // Unfortunately we don't have a way of getting the length of a signature without creating
        // one.
        let dummy_signature_bytes = self.sign(data, params)?;
        Ok(dummy_signature_bytes.len())
    }

    fn sign(
        &mut self,
        data: &[u8],
        params: &Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<Vec<u8>, Error> {
        let env = unsafe {
            JVM.as_mut().unwrap()
                .attach_current_thread()
                .expect("Unable to attach to current thread (Key::sign)")
        };
        let client_certificates_object = findClass("org/mozilla/gecko/ClientCertificates");
        let sign_params = SignParams::new(self.key_type_enum, data, params)?;
        let signing_algorithm: &JString = sign_params.get_algorithm();
        let data_to_sign = sign_params.get_data_to_sign();

        let key_global_ref = &self.key.0;
        let input: jbyteArray = env.byte_array_from_slice(&data_to_sign).unwrap();

        // Byte array signed by PrivateKey
        let signed_byte_array_object_result = unsafe {
            env.call_static_method(client_certificates_object,
                                   "sign",
                                   "([BLjava/security/PrivateKey;Ljava/lang/String;)[B",
                                   &[JValue::from(JObject::from_raw(input)),
                                       JValue::from(key_global_ref.as_obj()),
                                       JValue::from(*signing_algorithm)]).unwrap().l()
        };

        return match signed_byte_array_object_result {
            Ok(signed_byte_array_object) => {
                let signed_byte_array_result: jbyteArray = signed_byte_array_object.into_raw();
                let bytes_vec_result = env.convert_byte_array(signed_byte_array_result);
                match bytes_vec_result {
                    Ok(bytes_vec) => { Ok(bytes_vec) }
                    Err(_) => Err(error_here!(ErrorType::LibraryFailure))
                }
            }
            Err(_) => {
                Err(error_here!(ErrorType::LibraryFailure))
            }
        };
    }
}

// Attaches JVM to current thread and retrieves a JClass instance
#[no_mangle]
fn findClass(name: &str) -> JClass<'_> {
    unsafe {
        let env = JVM.as_mut().unwrap()
            .attach_current_thread()
            .expect("Unable to attach to current thread (findClass)");

        let class_name: JString = env
            .new_string(&name)
            .expect("Unable to create a java String!")
            .into();
        // We use cached classloader to find classes from Gecko's package
        let class_loader = CLASS_LOADER.as_mut().unwrap();
        let class_object = env.call_method_unchecked(&*class_loader,
                                                     CLASS_LOADER_FIND_CLASS_METHOD_ID.unwrap(),
                                                     jni::signature::ReturnType::Object,
                                                     &[JValue::from(class_name).to_jni()]).unwrap().l().unwrap();

        JClass::from(class_object)
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_org_mozilla_gecko_ClientCertificates_nativeInitialize(mut env: JNIEnv<'static>,
                                                                                  class: JClass<'static>,
                                                                                  classLoader: JObject<'static>,
) {
    android_logger::init_once(
        Config::default().with_max_level(LevelFilter::Trace),
    );

    unsafe {
        // Cache JVM instance during first Java to Rust call
        // It is required for attaching to JNIEnv from threads running in native code
        JVM = Some(env.get_java_vm().unwrap());
        // The class loader obtained from Android's main thread is also required for calling
        // package (non-system) methods from threads running in native code
        let class_loader_global_ref: GlobalRef = env.new_global_ref(classLoader).unwrap();
        let class_loader_class = env.find_class("java/lang/ClassLoader").unwrap();
        CLASS_LOADER = Some(class_loader_global_ref);
        CLASS_LOADER_FIND_CLASS_METHOD_ID = Some(env.get_method_id(class_loader_class, "findClass", "(Ljava/lang/String;)Ljava/lang/Class;").unwrap())
    }
}
