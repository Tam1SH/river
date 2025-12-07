pub trait SectionParser<TDocument, TResult> {
    fn parse_node(&self, document: &TDocument) -> miette::Result<TResult>;
}
