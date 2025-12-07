#[macro_export]
macro_rules! assert_err_contains {
    ($err_msg:expr, $expected:expr) => {
        #[cfg(test)]
        assert!(
            $err_msg.contains($expected),
            "expected: {}, got: {}",
            $expected,
            $err_msg
        );
    };
}
