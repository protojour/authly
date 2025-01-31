pub trait ResultExt<T, E> {
    fn handle_err(self, handler: &mut impl HandleError<E>) -> Option<T>;
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    fn handle_err(self, handler: &mut impl HandleError<E>) -> Option<T> {
        match self {
            Ok(value) => Some(value),
            Err(error) => {
                handler.handle(error);
                None
            }
        }
    }
}

pub trait HandleError<E> {
    fn handle(&mut self, error: E);
}
