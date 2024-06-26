mod stack_trace_debug;
use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn stack_trace_debug(args: TokenStream, input: TokenStream) -> TokenStream {
    stack_trace_debug::stack_trace_style_impl(args.into(), input.into()).into()
}
