//! Noise patterns presented on NoiseExplorer
//! https://noiseexplorer.com/patterns/

pub mod roles;

#[derive(PartialEq)]
pub enum Token {
    E,
    S,
    EE,
    ES,
    SE,
    SS,
    PSK,
}

pub struct MessagePattern {
    pub tokens: &'static [Token],
}

#[derive(Copy, Clone)]
pub struct HandshakePattern {
    pre_messages_initiator: &'static [Token],
    pre_messages_responder: &'static [Token],
    messages: &'static [MessagePattern],
}

impl HandshakePattern {
    pub const fn is_oneway(&self) -> bool {
        self.messages.len() == 1
    }

    pub const fn messages(&self) -> &'static [MessagePattern] {
        self.messages
    }

    pub const fn initiator_pre_messages(&self) -> &[Token] {
        self.pre_messages_initiator
    }

    pub const fn responder_pre_messages(&self) -> &[Token] {
        self.pre_messages_responder
    }

    pub const fn has_psk(&self) -> bool {
        let mut i = 0;
        while i < self.messages.len() {
            let tokens = self.messages[i].tokens;
            let mut j = 0;
            while j < tokens.len() {
                if matches!(tokens[j], Token::PSK) {
                    return true;
                }
                j += 1;
            }
            i += 1;
        }
        false
    }

    const fn contains_s(tokens: &[Token]) -> bool {
        let mut i = 0;
        while i < tokens.len() {
            if matches!(tokens[i], Token::S) {
                return true;
            }
            i += 1;
        }
        false
    }

    const fn contains_e(tokens: &[Token]) -> bool {
        let mut i = 0;
        while i < tokens.len() {
            if matches!(tokens[i], Token::E) {
                return true;
            }
            i += 1;
        }
        false
    }

    pub const fn peer_static_is_premessage(&self, is_initiator: bool) -> bool {
        let peer_pre = if is_initiator {
            self.pre_messages_responder
        } else {
            self.pre_messages_initiator
        };
        Self::contains_s(peer_pre)
    }

    pub const fn peer_ephemeral_is_premessage(&self, is_initiator: bool) -> bool {
        let peer_pre = if is_initiator {
            self.pre_messages_responder
        } else {
            self.pre_messages_initiator
        };
        Self::contains_e(peer_pre)
    }

    pub const fn local_static_required(&self, is_initiator: bool) -> bool {
        let own_pre = if is_initiator {
            self.pre_messages_initiator
        } else {
            self.pre_messages_responder
        };
        if Self::contains_s(own_pre) {
            return true;
        }
        let mut i = 0;
        while i < self.messages.len() {
            let sent_by_initiator = i % 2 == 0; // messages alternate, initiator sends first
            if sent_by_initiator == is_initiator && Self::contains_s(self.messages[i].tokens) {
                return true;
            }
            i += 1;
        }
        false
    }

    pub const fn local_ephemeral_required(&self, is_initiator: bool) -> bool {
        let own_pre = if is_initiator {
            self.pre_messages_initiator
        } else {
            self.pre_messages_responder
        };
        if Self::contains_e(own_pre) {
            return true;
        }

        false
    }
}

pub trait Pattern: Copy + 'static {
    const NAME: &'static str;
    const HANDSHAKE: HandshakePattern;
}

/// One-way patterns
#[derive(Copy, Clone)]
pub struct N;
impl Pattern for N {
    const NAME: &'static str = "N";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[Token::S],
        messages: &[MessagePattern {
            tokens: &[Token::E, Token::ES],
        }],
    };
}

#[derive(Copy, Clone)]
pub struct K;
impl Pattern for K {
    const NAME: &'static str = "K";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[Token::S],
        pre_messages_responder: &[Token::S],
        messages: &[MessagePattern {
            tokens: &[Token::E, Token::ES, Token::SS],
        }],
    };
}

#[derive(Copy, Clone)]
pub struct X;
impl Pattern for X {
    const NAME: &'static str = "X";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[Token::S],
        messages: &[MessagePattern {
            tokens: &[Token::E, Token::ES, Token::S, Token::SS],
        }],
    };
}

/// The 12 fundamental interactive handshake patterns
#[derive(Copy, Clone)]
pub struct NN;
impl Pattern for NN {
    const NAME: &'static str = "NN";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct NK;
impl Pattern for NK {
    const NAME: &'static str = "NK";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[Token::S],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::ES],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct NX;
impl Pattern for NX {
    const NAME: &'static str = "NX";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::S, Token::ES],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct XN;
impl Pattern for XN {
    const NAME: &'static str = "XN";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE],
            },
            MessagePattern {
                tokens: &[Token::S, Token::SE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct XK;
impl Pattern for XK {
    const NAME: &'static str = "XK";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[Token::S],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::ES],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE],
            },
            MessagePattern {
                tokens: &[Token::S, Token::SE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct XX;
impl Pattern for XX {
    const NAME: &'static str = "XX";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::S, Token::ES],
            },
            MessagePattern {
                tokens: &[Token::S, Token::SE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct KN;
impl Pattern for KN {
    const NAME: &'static str = "KN";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[Token::S],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct KK;
impl Pattern for KK {
    const NAME: &'static str = "KK";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[Token::S],
        pre_messages_responder: &[Token::S],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::ES, Token::SS],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct KX;
impl Pattern for KX {
    const NAME: &'static str = "KX";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[Token::S],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE, Token::S, Token::ES],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct IN;
impl Pattern for IN {
    const NAME: &'static str = "IN";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::S],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct IK;
impl Pattern for IK {
    const NAME: &'static str = "IK";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[Token::S],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::ES, Token::S, Token::SS],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct IX;
impl Pattern for IX {
    const NAME: &'static str = "IX";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::S],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE, Token::S, Token::ES],
            },
        ],
    };
}

/// The variantes with PSKs
#[derive(Copy, Clone)]
pub struct NNpsk0;
impl Pattern for NNpsk0 {
    const NAME: &'static str = "NNpsk0";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::PSK, Token::E],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct NNpsk2;
impl Pattern for NNpsk2 {
    const NAME: &'static str = "NNpsk2";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::PSK],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct NKpsk0;
impl Pattern for NKpsk0 {
    const NAME: &'static str = "NKpsk0";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[Token::S],
        messages: &[
            MessagePattern {
                tokens: &[Token::PSK, Token::E, Token::ES],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct NKpsk2;
impl Pattern for NKpsk2 {
    const NAME: &'static str = "NKpsk2";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[Token::S],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::ES],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::PSK],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct NXpsk2;
impl Pattern for NXpsk2 {
    const NAME: &'static str = "NXpsk2";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::S, Token::ES, Token::PSK],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct XNpsk3;
impl Pattern for XNpsk3 {
    const NAME: &'static str = "XNpsk3";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE],
            },
            MessagePattern {
                tokens: &[Token::S, Token::SE, Token::PSK],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct XKpsk3;
impl Pattern for XKpsk3 {
    const NAME: &'static str = "XKpsk3";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[Token::S],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::ES],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE],
            },
            MessagePattern {
                tokens: &[Token::S, Token::SE, Token::PSK],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct XXpsk3;
impl Pattern for XXpsk3 {
    const NAME: &'static str = "XXpsk3";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::S, Token::ES],
            },
            MessagePattern {
                tokens: &[Token::S, Token::SE, Token::PSK],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct KNpsk0;
impl Pattern for KNpsk0 {
    const NAME: &'static str = "KNpsk0";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[Token::S],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::PSK, Token::E],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct KNpsk2;
impl Pattern for KNpsk2 {
    const NAME: &'static str = "KNpsk2";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[Token::S],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE, Token::PSK],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct KKpsk0;
impl Pattern for KKpsk0 {
    const NAME: &'static str = "KKpsk0";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[Token::S],
        pre_messages_responder: &[Token::S],
        messages: &[
            MessagePattern {
                tokens: &[Token::PSK, Token::E, Token::ES, Token::SS],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct KKpsk2;
impl Pattern for KKpsk2 {
    const NAME: &'static str = "KKpsk2";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[Token::S],
        pre_messages_responder: &[Token::S],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::ES, Token::SS],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE, Token::PSK],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct KXpsk2;
impl Pattern for KXpsk2 {
    const NAME: &'static str = "KXpsk2";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[Token::S],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E],
            },
            MessagePattern {
                tokens: &[
                    Token::E,
                    Token::EE,
                    Token::SE,
                    Token::S,
                    Token::ES,
                    Token::PSK,
                ],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct INpsk1;
impl Pattern for INpsk1 {
    const NAME: &'static str = "INpsk1";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::S, Token::PSK],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct INpsk2;
impl Pattern for INpsk2 {
    const NAME: &'static str = "INpsk2";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::S],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE, Token::PSK],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct IKpsk1;
impl Pattern for IKpsk1 {
    const NAME: &'static str = "IKpsk1";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[Token::S],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::ES, Token::S, Token::SS, Token::PSK],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct IKpsk2;
impl Pattern for IKpsk2 {
    const NAME: &'static str = "IKpsk2";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[Token::S],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::ES, Token::S, Token::SS],
            },
            MessagePattern {
                tokens: &[Token::E, Token::EE, Token::SE, Token::PSK],
            },
        ],
    };
}

#[derive(Copy, Clone)]
pub struct IXpsk2;
impl Pattern for IXpsk2 {
    const NAME: &'static str = "IXpsk2";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[],
        messages: &[
            MessagePattern {
                tokens: &[Token::E, Token::S],
            },
            MessagePattern {
                tokens: &[
                    Token::E,
                    Token::EE,
                    Token::SE,
                    Token::S,
                    Token::ES,
                    Token::PSK,
                ],
            },
        ],
    };
}

/// One-way patterns with PSK
#[derive(Copy, Clone)]
pub struct Npsk0;
impl Pattern for Npsk0 {
    const NAME: &'static str = "Npsk0";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[Token::S],
        messages: &[MessagePattern {
            tokens: &[Token::PSK, Token::E, Token::ES],
        }],
    };
}

#[derive(Copy, Clone)]
pub struct Kpsk0;
impl Pattern for Kpsk0 {
    const NAME: &'static str = "Kpsk0";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[Token::S],
        pre_messages_responder: &[Token::S],
        messages: &[MessagePattern {
            tokens: &[Token::PSK, Token::E, Token::ES, Token::SS],
        }],
    };
}

#[derive(Copy, Clone)]
pub struct Xpsk1;
impl Pattern for Xpsk1 {
    const NAME: &'static str = "Xpsk1";
    const HANDSHAKE: HandshakePattern = HandshakePattern {
        pre_messages_initiator: &[],
        pre_messages_responder: &[Token::S],
        messages: &[MessagePattern {
            tokens: &[Token::E, Token::ES, Token::S, Token::SS, Token::PSK],
        }],
    };
}
