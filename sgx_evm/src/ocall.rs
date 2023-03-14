use crate::querier::{GoQuerier, QueryResult};
use crate::error::GoError;
use crate::memory::U8SliceView;

extern "C" {
    pub fn query(q: *mut GoQuerier, req: U8SliceView) -> QueryResult;
}
