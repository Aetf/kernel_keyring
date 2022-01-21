use pamsm::{pam_module, Pam, PamError, PamFlag, PamLibExt as _, PamServiceModule};
use std::ffi::CString;
use syslog::{Facility, Formatter3164, BasicLogger};
use std::sync::Once;
use std::thread;
use keyutils::{Key, keytypes, Keyring, SpecialKeyring};

fn read_key_thread(ring: &Keyring, desc: &str) -> Result<Vec<u8>, keyutils::Error> {
    // link ring to our thread keyring
    let mut thread_ring = Keyring::attach_or_create(SpecialKeyring::Thread)?;
    log::debug!("Got my thread keyring: {:?}", &thread_ring);
    thread_ring.link_keyring(&ring)?;
    log::debug!("Linked {:?} to {:?}", &ring, &thread_ring);

    let key = Key::request::<keytypes::User, _, _, _>(desc, None, None)?;
    log::debug!("Got user key: {:?}", &key);

    let content = key.read()?;
    Ok(content)
}

fn read_key(ring: Keyring, desc: &'static str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // to read a key, we must possess the key from one of the anchor keyrings
    // we use the thread keyring from a new thread for this purpose to avoid
    // affecting the application calling PAM.

    let handle = thread::spawn(move || {
        read_key_thread(&ring, desc)
    });

    let res = handle.join().unwrap();

    res.map_err(Into::into)
}

fn auth(pamh: Pam, _flags: PamFlag, args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    if let Some("clear") = args.get(0).map(String::as_str) {
        pamh.set_authtok(None).map_err(|e| format!("Got pam error when set authtok {:?}", &e))?;
        return Ok(());
    }

    // systemd-cryptsetup saves the key in root's user keyring under the name 'cryptsetup'
    // get the user's keyring
    let ring = Keyring::attach(SpecialKeyring::User)?;
    // bail if it's not the root user
    if ring.description()?.uid != 0 {
        return Err("Can not get root's user keyring".into());
    }

    let content = read_key(ring, "cryptsetup")?;
    log::debug!("Got user key content");

    // the content may contain multiple passwords separated by a null byte,
    // we only want the last one
    let content = content.rsplit(|b| *b == 0)
        .skip_while(|slice| slice.is_empty())
        .next()
        .ok_or("Cached password is empty")?;
    let cached_password = CString::new(content)?;

    pamh.set_authtok(Some(&cached_password)).map_err(|e| format!("Got pam error when set authtok {:?}", &e))?;

    log::debug!("Set authtok done");
    Ok(())
}

fn init_logging() -> Result<(), Box<dyn std::error::Error>> {
    let log_writer = syslog::unix(Formatter3164 {
        facility: Facility::LOG_AUTHPRIV,
        hostname: None,
        process: "pam_kernel_keyring".into(),
        pid: 0,
    })?;
    log::set_boxed_logger(Box::new(BasicLogger::new(log_writer)))?;
    log::set_max_level(log::LevelFilter::Debug);
    Ok(())
}

static C_LIB_INIT: Once = Once::new();
static mut C_LIB_INITIALIZED: bool = false;
fn auth_wrapper(pamh: Pam, flags: PamFlag, args: Vec<String>) -> Result<(), PamError> {
    C_LIB_INIT.call_once(|| {
        match init_logging() {
            // Safety: accessing the `static mut` is unsafe, but if we do so in a synchronized
            // fashion (e.g., write once or read all) then we're good to go
            Ok(_) => unsafe { C_LIB_INITIALIZED = true; },
            Err(e) => {
                println!("Error when init logging: {:?}", e)
            }
        }
    });
    // Safety: accessing the `static mut` is unsafe, but if we do so in a synchronized
    // fashion (e.g., write once or read all) then we're good to go
    unsafe {
        if !C_LIB_INITIALIZED {
            return Err(PamError::AUTHINFO_UNAVAIL);
        }
    }

    auth(pamh, flags, args).map_err(|e| {
        log::debug!("Got error {:?}", &e);
        PamError::AUTHINFO_UNAVAIL
    })
}

struct PamKernelKeyring;

impl PamServiceModule for PamKernelKeyring {
    fn authenticate(pamh: Pam, flags: PamFlag, args: Vec<String>) -> PamError {
        match auth_wrapper(pamh, flags, args) {
            Ok(_) => PamError::SUCCESS,
            Err(e) => e,
        }
    }
    fn setcred(_: Pam, _: PamFlag, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

pam_module!(PamKernelKeyring);
