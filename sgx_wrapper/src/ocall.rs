use crate::error::GoError;
use crate::querier::{GoQuerier, QueryResult};
use crate::memory::U8SliceView;

extern "C" {
    pub fn query(q: GoQuerier, req: U8SliceView) -> QueryResult;
}
