use crate::ast::*;
use crate::lexer::Token;
use crate::CompileError;
use logos::Logos;

pub struct Parser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    _source: &'a str,
    /// How many nested grammar productions are open right now.
    ///
    /// The parser is recursive descent, so a nested source construct is a
    /// nested stack frame. Nothing in the grammar bounds that nesting, and a
    /// bounded input can therefore describe an unbounded stack: the fuzzer
    /// found it with a run of open parentheses, which drives `parse_primary`
    /// back into `parse_expr` once per character.
    ///
    /// A stack overflow is not a `Result`. It aborts the process, so no
    /// caller can catch it and the usual "returns an error on bad input"
    /// contract does not hold. Counting the depth is what turns that abort
    /// back into a value the caller can handle.
    depth: u32,
}

/// How deeply source constructs may nest.
///
/// Chosen against the two failures it sits between, and sized for the
/// tighter one.
///
/// One level of source nesting is five stack frames, not one: an expression
/// descends through comparison, arithmetic, term and postfix parsing before
/// `parse_primary` can recurse. Thirty-two levels is therefore 160 frames,
/// which stays inside a quarter-megabyte stack even at two kilobytes a
/// frame. The bound is set against the sanitiser build rather than the
/// release one: that build caught the overflow, its frames are the largest
/// and its stack the shallowest, and a limit that only held in release would
/// let the crash straight back into the fuzzer.
///
/// The headroom above real programs is still large. The deepest hand-written
/// contract in this tree nests seven levels.
///
/// It is a parser limit rather than a language limit. A contract that needs
/// more nesting than this is not rejected by the chain, it is rejected by the
/// front end, and the message says so.
pub const MAX_NESTING_DEPTH: u32 = 32;

impl<'a> Parser<'a> {
    pub fn new(source: &'a str) -> Result<Self, CompileError> {
        let mut lexer = Token::lexer(source);
        let mut tokens = Vec::new();
        while let Some(res) = lexer.next() {
            match res {
                Ok(tok) => tokens.push(tok),
                Err(()) => {
                    let span = lexer.span();
                    let line = source[..span.start].lines().count().saturating_add(1);
                    let snippet = if span.end <= source.len() {
                        &source[span.start..span.end]
                    } else {
                        &source[span.start..]
                    };
                    return Err(CompileError::LexerError(format!(
                        "unexpected token at line {}: `{}` (bytes {}..{})",
                        line, snippet, span.start, span.end
                    )));
                }
            }
        }
        Ok(Self {
            tokens,
            pos: 0,
            _source: source,
            depth: 0,
        })
    }

    /// Open one level of nesting, or refuse.
    ///
    /// Paired with [`Self::leave`]. Every production that can reach itself
    /// again calls this first, so the count tracks stack frames rather than
    /// any one syntactic form: it is the recursion that overflows, and which
    /// keyword opened it does not change that.
    fn enter(&mut self) -> Result<(), CompileError> {
        if self.depth >= MAX_NESTING_DEPTH {
            return Err(CompileError::ParserError(format!(
                "expression or statement nests deeper than {MAX_NESTING_DEPTH} levels"
            )));
        }
        self.depth += 1;
        Ok(())
    }

    /// Close one level of nesting.
    ///
    /// Saturating, so a mismatched pair cannot wrap the counter to a huge
    /// number and disable the limit for the rest of the parse.
    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn peek(&self) -> &Token {
        if self.pos < self.tokens.len() {
            &self.tokens[self.pos]
        } else {
            &Token::Error
        }
    }

    fn consume(&mut self) -> Token {
        let t = self.peek().clone();
        self.pos += 1;
        t
    }

    fn expect(&mut self, expected: Token) -> Result<(), CompileError> {
        let t = self.consume();
        if t != expected {
            return Err(CompileError::ParserError(format!(
                "Expected {:?}, found {:?}",
                expected, t
            )));
        }
        Ok(())
    }

    pub fn parse_contract(&mut self) -> Result<Contract, CompileError> {
        self.expect(Token::Contract)?;
        let name = if let Token::Ident(name) = self.consume() {
            name
        } else {
            return Err(CompileError::ParserError(
                "Expected contract name".to_string(),
            ));
        };

        self.expect(Token::BraceOpen)?;

        let mut functions = Vec::new();
        let mut storage = Vec::new();
        let mut structs = Vec::new();

        while self.peek() != &Token::BraceClose {
            match self.peek() {
                Token::Storage => {
                    self.consume();
                    self.expect(Token::BraceOpen)?;
                    while self.peek() != &Token::BraceClose {
                        let name = if let Token::Ident(name) = self.consume() {
                            name
                        } else {
                            return Err(CompileError::ParserError("Expected name".to_string()));
                        };
                        self.expect(Token::Colon)?;
                        let ty = if let Token::Ident(ty) = self.consume() {
                            if ty == "Map" {
                                self.expect(Token::Lt)?;
                                let k = if let Token::Ident(k) = self.consume() {
                                    k
                                } else {
                                    return Err(CompileError::ParserError(
                                        "Expected map key type".to_string(),
                                    ));
                                };
                                self.expect(Token::Comma)?;
                                let v = if let Token::Ident(v) = self.consume() {
                                    v
                                } else {
                                    return Err(CompileError::ParserError(
                                        "Expected map value type".to_string(),
                                    ));
                                };
                                self.expect(Token::Gt)?;
                                format!("Map<{k},{v}>")
                            } else {
                                ty
                            }
                        } else {
                            return Err(CompileError::ParserError("Expected type".to_string()));
                        };
                        self.expect(Token::Comma)?;
                        storage.push(StorageField { name, ty });
                    }
                    self.expect(Token::BraceClose)?;
                }
                Token::Struct => {
                    self.consume();
                    let name = if let Token::Ident(name) = self.consume() {
                        name
                    } else {
                        return Err(CompileError::ParserError("Expected name".to_string()));
                    };
                    self.expect(Token::BraceOpen)?;
                    let mut fields = Vec::new();
                    while self.peek() != &Token::BraceClose {
                        let fname = if let Token::Ident(n) = self.consume() {
                            n
                        } else {
                            return Err(CompileError::ParserError("Expected name".to_string()));
                        };
                        self.expect(Token::Colon)?;
                        let fty = if let Token::Ident(t) = self.consume() {
                            t
                        } else {
                            return Err(CompileError::ParserError("Expected type".to_string()));
                        };
                        self.expect(Token::Comma)?;
                        fields.push(StorageField {
                            name: fname,
                            ty: fty,
                        });
                    }
                    self.expect(Token::BraceClose)?;
                    structs.push(Struct { name, fields });
                }
                _ => {
                    functions.push(self.parse_function()?);
                }
            }
        }
        self.expect(Token::BraceClose)?;

        Ok(Contract {
            name,
            storage,
            structs,
            functions,
        })
    }

    fn parse_function(&mut self) -> Result<Function, CompileError> {
        let is_pub = if self.peek() == &Token::Pub {
            self.consume();
            true
        } else {
            false
        };

        self.expect(Token::Fn)?;
        let name = if let Token::Ident(name) = self.consume() {
            name
        } else {
            return Err(CompileError::ParserError(
                "Expected function name".to_string(),
            ));
        };

        self.expect(Token::ParenOpen)?;
        let mut params = Vec::new();
        while self.peek() != &Token::ParenClose {
            let name = if let Token::Ident(name) = self.consume() {
                name
            } else {
                return Err(CompileError::ParserError("Expected param name".to_string()));
            };
            self.expect(Token::Colon)?;
            let ty = if let Token::Ident(ty) = self.consume() {
                ty
            } else {
                return Err(CompileError::ParserError("Expected param type".to_string()));
            };
            params.push(Param { name, ty });
            if self.peek() == &Token::Comma {
                self.consume();
            }
        }
        self.expect(Token::ParenClose)?;

        let mut return_type = None;
        if self.peek() == &Token::Arrow {
            self.consume();
            if let Token::Ident(ty) = self.consume() {
                return_type = Some(ty);
            } else {
                return Err(CompileError::ParserError(
                    "Expected return type".to_string(),
                ));
            }
        }

        self.expect(Token::BraceOpen)?;
        let mut body = Vec::new();
        while self.peek() != &Token::BraceClose {
            body.push(self.parse_stmt()?);
        }
        self.expect(Token::BraceClose)?;

        Ok(Function {
            name,
            params,
            return_type,
            body,
            is_pub,
        })
    }

    /// Parse a statement, counting the nesting it opens.
    ///
    /// Block-bearing statements recurse into this function for their bodies,
    /// so nested blocks are a second route to the same overflow that nested
    /// expressions take. Both routes share one counter: a source file that
    /// alternates between them nests just as deep as one that does not, and
    /// two separate budgets would each see half of it.
    fn parse_stmt(&mut self) -> Result<Stmt, CompileError> {
        self.enter()?;
        let parsed = self.parse_stmt_inner();
        self.leave();
        parsed
    }

    fn parse_stmt_inner(&mut self) -> Result<Stmt, CompileError> {
        match self.peek() {
            Token::Let => {
                self.consume();
                let name = if let Token::Ident(name) = self.consume() {
                    name
                } else {
                    return Err(CompileError::ParserError(
                        "Expected identifier after let".to_string(),
                    ));
                };
                self.expect(Token::Assign)?;
                let expr = self.parse_expr()?;
                self.expect(Token::Semicolon)?;
                Ok(Stmt::Let(name, expr))
            }
            Token::Constrain => {
                self.consume();
                self.expect(Token::ParenOpen)?;
                let expr = self.parse_expr()?;
                self.expect(Token::ParenClose)?;
                self.expect(Token::Semicolon)?;
                Ok(Stmt::Constrain(expr))
            }
            Token::Storage => {
                self.consume();
                self.expect(Token::Colon)?;
                self.expect(Token::Colon)?;
                let name = if let Token::Ident(name) = self.consume() {
                    name
                } else {
                    return Err(CompileError::ParserError("Expected name".to_string()));
                };
                self.expect(Token::Assign)?;
                let expr = self.parse_expr()?;
                self.expect(Token::Semicolon)?;
                Ok(Stmt::StorageWrite(name, expr))
            }
            Token::If => {
                self.consume();
                self.expect(Token::ParenOpen)?;
                let cond = self.parse_expr()?;
                self.expect(Token::ParenClose)?;
                self.expect(Token::BraceOpen)?;
                let mut then_branch = Vec::new();
                while self.peek() != &Token::BraceClose {
                    then_branch.push(self.parse_stmt()?);
                }
                self.expect(Token::BraceClose)?;

                let mut else_branch = None;
                if self.peek() == &Token::Else {
                    self.consume();
                    self.expect(Token::BraceOpen)?;
                    let mut eb = Vec::new();
                    while self.peek() != &Token::BraceClose {
                        eb.push(self.parse_stmt()?);
                    }
                    self.expect(Token::BraceClose)?;
                    else_branch = Some(eb);
                }
                Ok(Stmt::If(cond, then_branch, else_branch))
            }
            Token::While => {
                self.consume();
                self.expect(Token::ParenOpen)?;
                let cond = self.parse_expr()?;
                self.expect(Token::ParenClose)?;
                self.expect(Token::BraceOpen)?;
                let mut body = Vec::new();
                while self.peek() != &Token::BraceClose {
                    body.push(self.parse_stmt()?);
                }
                self.expect(Token::BraceClose)?;
                Ok(Stmt::While(cond, body))
            }
            Token::Match => {
                self.consume();
                self.expect(Token::ParenOpen)?;
                let scrutinee = self.parse_expr()?;
                self.expect(Token::ParenClose)?;
                self.expect(Token::BraceOpen)?;
                let mut arms = Vec::new();
                loop {
                    if self.peek() == &Token::BraceClose {
                        break;
                    }
                    if self.peek() == &Token::Comma {
                        self.consume();
                        if self.peek() == &Token::BraceClose {
                            break;
                        }
                        continue;
                    }
                    arms.push(self.parse_match_arm()?);
                    if self.peek() == &Token::Comma {
                        self.consume();
                    } else if self.peek() == &Token::BraceClose {
                        break;
                    } else {
                        return Err(CompileError::ParserError(
                            "expected ',' or '\x7D' after match arm".to_string(),
                        ));
                    }
                }
                self.expect(Token::BraceClose)?;
                self.expect(Token::Semicolon)?;
                Ok(Stmt::Match { scrutinee, arms })
            }
            Token::For => {
                self.consume();
                let var = if let Token::Ident(name) = self.consume() {
                    name
                } else {
                    return Err(CompileError::ParserError(
                        "Expected loop variable after for".to_string(),
                    ));
                };
                self.expect(Token::In)?;
                let start = self.parse_expr()?;
                self.expect(Token::DotDot)?;
                let end = self.parse_expr()?;
                self.expect(Token::BraceOpen)?;
                let mut body = Vec::new();
                while self.peek() != &Token::BraceClose {
                    body.push(self.parse_stmt()?);
                }
                self.expect(Token::BraceClose)?;
                Ok(Stmt::For {
                    var,
                    start,
                    end,
                    body,
                })
            }
            Token::Return => {
                self.consume();
                let expr = if self.peek() != &Token::Semicolon {
                    Some(self.parse_expr()?)
                } else {
                    None
                };
                self.expect(Token::Semicolon)?;
                Ok(Stmt::Return(expr))
            }
            Token::Ident(name) if name == "emit" => {
                self.consume();
                let event_name = if let Token::Ident(en) = self.consume() {
                    en
                } else {
                    return Err(CompileError::ParserError("Expected event name".to_string()));
                };
                self.expect(Token::ParenOpen)?;
                let mut args = Vec::new();
                while self.peek() != &Token::ParenClose {
                    args.push(self.parse_expr()?);
                    if self.peek() == &Token::Comma {
                        self.consume();
                    }
                }
                self.expect(Token::ParenClose)?;
                self.expect(Token::Semicolon)?;
                Ok(Stmt::Emit(event_name, args))
            }
            Token::Ident(name) => {
                let name = name.clone();
                self.consume();
                if self.peek() == &Token::BracketOpen {
                    self.consume();
                    let key = self.parse_expr()?;
                    self.expect(Token::BracketClose)?;
                    self.expect(Token::Assign)?;
                    let val = self.parse_expr()?;
                    self.expect(Token::Semicolon)?;
                    Ok(Stmt::MappingWrite(name, key, val))
                } else {
                    self.expect(Token::Assign)?;
                    let expr = self.parse_expr()?;
                    self.expect(Token::Semicolon)?;
                    Ok(Stmt::Assign(name, expr))
                }
            }
            _ => {
                let expr = self.parse_expr()?;
                self.expect(Token::Semicolon)?;
                Ok(Stmt::Expr(expr))
            }
        }
    }

    /// Parse an expression, counting the nesting it opens.
    ///
    /// The guard sits here rather than at `parse_primary` because this is the
    /// function a nested construct comes back to: a parenthesis, a call
    /// argument, an index. Counting at the point of re-entry means one
    /// increment per stack frame that can recurse, which is the quantity that
    /// has to stay bounded.
    fn parse_expr(&mut self) -> Result<Expr, CompileError> {
        self.enter()?;
        let parsed = self.parse_expr_inner();
        self.leave();
        parsed
    }

    fn parse_expr_inner(&mut self) -> Result<Expr, CompileError> {
        let mut left = self.parse_arith()?;

        while matches!(
            self.peek(),
            Token::Eq | Token::Neq | Token::Lt | Token::Gt | Token::Lte | Token::Gte
        ) {
            let op = match self.consume() {
                Token::Eq => BinOp::Eq,
                Token::Neq => BinOp::Neq,
                Token::Lt => BinOp::Lt,
                Token::Gt => BinOp::Gt,
                Token::Lte => BinOp::Lte,
                Token::Gte => BinOp::Gte,
                _ => unreachable!(),
            };
            let right = self.parse_arith()?;
            left = Expr::Binary(Box::new(left), op, Box::new(right));
        }

        Ok(left)
    }

    fn parse_arith(&mut self) -> Result<Expr, CompileError> {
        let mut left = self.parse_term()?;

        while matches!(self.peek(), Token::Plus | Token::Minus) {
            let op = match self.consume() {
                Token::Plus => BinOp::Add,
                Token::Minus => BinOp::Sub,
                _ => unreachable!(),
            };
            let right = self.parse_term()?;
            left = Expr::Binary(Box::new(left), op, Box::new(right));
        }

        Ok(left)
    }

    fn parse_postfix(&mut self) -> Result<Expr, CompileError> {
        let mut expr = self.parse_primary()?;
        while self.peek() == &Token::Dot {
            self.consume();
            let field = if let Token::Ident(f) = self.consume() {
                f
            } else {
                return Err(CompileError::ParserError(
                    "Expected field name after dot".to_string(),
                ));
            };
            expr = Expr::FieldAccess(Box::new(expr), field);
        }
        Ok(expr)
    }

    fn parse_term(&mut self) -> Result<Expr, CompileError> {
        let mut left = self.parse_postfix()?;

        while matches!(self.peek(), Token::Star | Token::Slash) {
            let op = match self.consume() {
                Token::Star => BinOp::Mul,
                Token::Slash => BinOp::Div,
                _ => unreachable!(),
            };
            let right = self.parse_postfix()?;
            left = Expr::Binary(Box::new(left), op, Box::new(right));
        }

        Ok(left)
    }

    fn parse_match_arm(&mut self) -> Result<MatchArm, CompileError> {
        let pattern = match self.peek() {
            Token::Ident(name) if name == "_" => {
                self.consume();
                MatchPattern::Wildcard
            }
            Token::Int(val) => {
                let v = *val;
                self.consume();
                MatchPattern::IntLit(v)
            }
            _ => {
                return Err(CompileError::ParserError(
                    "match arm pattern must be an integer literal or '_'".to_string(),
                ));
            }
        };
        self.expect(Token::FatArrow)?;
        let mut body = Vec::new();
        if self.peek() == &Token::BraceOpen {
            self.consume();
            while self.peek() != &Token::BraceClose {
                body.push(self.parse_stmt()?);
            }
            self.expect(Token::BraceClose)?;
        } else {
            body.push(self.parse_stmt()?);
        }
        Ok(MatchArm { pattern, body })
    }

    fn parse_primary(&mut self) -> Result<Expr, CompileError> {
        match self.consume() {
            Token::Int(val) => Ok(Expr::Int(val)),
            Token::Hex(val) => {
                let s = val.strip_prefix("0x").unwrap_or(&val);
                let num = u64::from_str_radix(s, 16).map_err(|e| {
                    CompileError::ParserError(format!("Invalid hex literal {val}: {e}"))
                })?;
                Ok(Expr::Int(num))
            }
            Token::ParenOpen => {
                let expr = self.parse_expr()?;
                self.expect(Token::ParenClose)?;
                Ok(expr)
            }
            Token::Ident(name) => {
                if name == "poseidon" {
                    self.expect(Token::ParenOpen)?;
                    let mut args = Vec::new();
                    while self.peek() != &Token::ParenClose {
                        args.push(self.parse_expr()?);
                        if self.peek() == &Token::Comma {
                            self.consume();
                        }
                    }
                    self.expect(Token::ParenClose)?;
                    Ok(Expr::Call("poseidon".to_string(), args))
                } else if name == "msg" {
                    self.expect(Token::Colon)?;
                    self.expect(Token::Colon)?;
                    let field = if let Token::Ident(f) = self.consume() {
                        f
                    } else {
                        return Err(CompileError::ParserError("Expected field".to_string()));
                    };
                    self.expect(Token::ParenOpen)?;
                    self.expect(Token::ParenClose)?;
                    Ok(Expr::Call(format!("msg::{field}"), Vec::new()))
                } else if name == "block" {
                    self.expect(Token::Colon)?;
                    self.expect(Token::Colon)?;
                    let field = if let Token::Ident(f) = self.consume() {
                        f
                    } else {
                        return Err(CompileError::ParserError("Expected field".to_string()));
                    };
                    self.expect(Token::ParenOpen)?;
                    self.expect(Token::ParenClose)?;
                    Ok(Expr::Call(format!("block::{field}"), Vec::new()))
                } else if name == "verify_merkle_proof" {
                    self.expect(Token::ParenOpen)?;
                    let root = self.parse_expr()?;
                    self.expect(Token::Comma)?;
                    let leaf = self.parse_expr()?;
                    self.expect(Token::Comma)?;
                    let path = self.parse_expr()?;
                    self.expect(Token::ParenClose)?;
                    Ok(Expr::Call(
                        "verify_merkle_proof".to_string(),
                        vec![root, leaf, path],
                    ))
                } else if self.peek() == &Token::ParenOpen {
                    self.consume();
                    let mut args = Vec::new();
                    while self.peek() != &Token::ParenClose {
                        args.push(self.parse_expr()?);
                        if self.peek() == &Token::Comma {
                            self.consume();
                        }
                    }
                    self.expect(Token::ParenClose)?;
                    Ok(Expr::Call(name, args))
                } else if self.peek() == &Token::BracketOpen {
                    self.consume();
                    let key = self.parse_expr()?;
                    self.expect(Token::BracketClose)?;
                    Ok(Expr::MappingRead(name, Box::new(key)))
                } else if self.peek() == &Token::BraceOpen {
                    self.consume();
                    let mut fields = Vec::new();
                    while self.peek() != &Token::BraceClose {
                        let fname = if let Token::Ident(f) = self.consume() {
                            f
                        } else {
                            return Err(CompileError::ParserError(
                                "Expected struct field name".to_string(),
                            ));
                        };
                        self.expect(Token::Colon)?;
                        let val = self.parse_expr()?;
                        fields.push((fname, val));
                        if self.peek() == &Token::Comma {
                            self.consume();
                        }
                    }
                    self.expect(Token::BraceClose)?;
                    Ok(Expr::StructLiteral(name, fields))
                } else {
                    Ok(Expr::Ident(name))
                }
            }
            Token::Storage => {
                self.expect(Token::Colon)?;
                self.expect(Token::Colon)?;
                let name = if let Token::Ident(name) = self.consume() {
                    name
                } else {
                    return Err(CompileError::ParserError("Expected name".to_string()));
                };
                Ok(Expr::StorageRead(name))
            }
            _ => Err(CompileError::ParserError(
                "Expected primary expression".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompileError;

    /// Build the source the fuzzer found, at a chosen nesting depth.
    fn nested_parens(depth: usize) -> String {
        format!(
            "contract T {{ pub fn main() {{ let x = {}1{}; }} }}",
            "(".repeat(depth),
            ")".repeat(depth)
        )
    }

    #[test]
    fn deeply_nested_parentheses_return_an_error_instead_of_overflowing() {
        // The shape of the crashing input, an order of magnitude past the
        // limit. Before the guard this aborted the process under the
        // sanitiser, which is why the assertion is that a value comes back at
        // all: `is_err` is the observable difference between a refusal and an
        // abort.
        let source = nested_parens(MAX_NESTING_DEPTH as usize * 10);
        let mut parser = Parser::new(&source).expect("the input lexes");
        let parsed = parser.parse_contract();
        assert!(matches!(parsed, Err(CompileError::ParserError(_))));
    }

    #[test]
    fn unbalanced_open_parentheses_also_return_rather_than_overflow() {
        // The fuzzer's input does not have to close what it opens, and the
        // run of opens is what drives the recursion. Closing brackets are
        // the parser's problem after the depth guard, not before it.
        let source = format!("contract T {{ pub fn main() {{ let x = {}", "(".repeat(4096));
        let mut parser = Parser::new(&source).expect("the input lexes");
        assert!(parser.parse_contract().is_err());
    }

    #[test]
    fn nesting_within_the_limit_still_parses() {
        // The bound has to leave real programs alone. Ten levels is deeper
        // than any contract in this tree and well inside the limit.
        let source = nested_parens(10);
        let mut parser = Parser::new(&source).expect("the input lexes");
        assert!(parser.parse_contract().is_ok());
    }

    #[test]
    fn nested_blocks_share_the_expression_budget() {
        // Statements recurse too. Were the two counted separately, a file
        // alternating between them would reach twice the intended depth.
        let opens = "if (1) {".repeat(MAX_NESTING_DEPTH as usize * 2);
        let closes = "}".repeat(MAX_NESTING_DEPTH as usize * 2);
        let source = format!("contract T {{ pub fn main() {{ {opens} {closes} }} }}");
        let mut parser = Parser::new(&source).expect("the input lexes");
        assert!(parser.parse_contract().is_err());
    }

    #[test]
    fn the_counter_unwinds_so_sibling_expressions_do_not_accumulate() {
        // `leave` has to run on the way out of every production, including
        // the ones that returned an error deeper in. A leaked increment would
        // make a long flat function fail once it had parsed enough siblings,
        // which is a bug that only appears in large inputs.
        let mut body = String::new();
        for i in 0..500 {
            body.push_str(&format!("let v{i} = ((({i})));"));
        }
        let source = format!("contract T {{ pub fn main() {{ {body} }} }}");
        let mut parser = Parser::new(&source).expect("the input lexes");
        assert!(parser.parse_contract().is_ok());
    }
}
