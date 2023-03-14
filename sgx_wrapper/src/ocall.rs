use crate::error::GoError;
use crate::querier::{GoQuerier, QueryResult};
use crate::memory::U8SliceView;

pub extern "C" fn query(q: *mut GoQuerier, req: U8SliceView) -> QueryResult {
    let querier: Box<GoQuerier> = unsafe {Box::from_raw(q)};
    querier.make_query(req)
}
