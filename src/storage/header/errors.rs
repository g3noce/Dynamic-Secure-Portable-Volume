use std::fmt;

#[derive(Debug)]
pub enum HeaderError {
    ReadIvFailed,
    ReadSizeFailed,
    ReadReservedFailed,
    ReadMacTagFailed,
    WriteIvFailed,
    WriteSizeFailed,
    WriteReservedFailed,
    WriteMacTagFailed,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (func, cause) = match self {
            HeaderError::ReadIvFailed => ("read_from", "failed to read IV"),
            HeaderError::ReadSizeFailed => ("read_from", "failed to read logical size"),
            HeaderError::ReadReservedFailed => ("read_from", "failed to read reserved area"),
            HeaderError::ReadMacTagFailed => ("read_from", "failed to read MAC tag"),
            HeaderError::WriteIvFailed => ("write_to", "failed to write IV"),
            HeaderError::WriteSizeFailed => ("write_to", "failed to write logical size"),
            HeaderError::WriteReservedFailed => ("write_to", "failed to write reserved area"),
            HeaderError::WriteMacTagFailed => ("write_to", "failed to write MAC tag"),
        };
        write!(f, "mod: header, function: {}, cause: {}", func, cause)
    }
}

impl std::error::Error for HeaderError {}
