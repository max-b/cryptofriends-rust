use std::error;
use std::result;
use std::fmt::{self, Display, Formatter};
use openssl;

#[derive(Debug)]
enum Error {
    OpenSSL(openssl::error::ErrorStack),
}

impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Error::OpenSSL(ref error) => error.fmt(formatter),
        }
    }
}

impl error::Error for Error {
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(error: openssl::error::ErrorStack) -> Self {
        Error::OpenSSL(error)
    }
}

type Result<T> = result::Result<T, Error>;
