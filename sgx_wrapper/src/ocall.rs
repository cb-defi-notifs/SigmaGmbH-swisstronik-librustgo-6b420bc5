use crate::error::GoError;
use crate::querier::{GoQuerier, QueryResult};
use crate::memory::U8SliceView;

pub extern "C" fn query(q: GoQuerier, req: U8SliceView) -> QueryResult {
    q.make_query(req)
}
