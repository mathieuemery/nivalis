//! Noise patterns presented on NoiseExplorer
//! https://noiseexplorer.com/patterns/

pub mod roles;

/// A single token in a Noise message pattern (one step).
#[derive(PartialEq)]
pub enum Token {
    /// Generate and send an ephemeral public key
    /// to the buffer
    E,
    /// Append encrypt_and_hash(s.public_key) to the buffer
    S,
    /// Call mix_key(DH(e, re))
    EE,
    /// Call mix_key(DH(e, rs)) or mix_key(DH(s, re))
    /// depending on the role
    ES,
    /// Call mix_key(DH(s, re)) or mix_key(DH(e, rs))
    /// depending on the role
    SE,
    /// Call mix_key(DH(s, rs))
    SS,
    /// Call mix_key_and_hash(psk)
    PSK,
}

/// The sequence of [`Token`]s exchanged in a single handshake message
pub struct MessagePattern {
    /// Tokens processed in order for this message
    pub tokens: &'static [Token],
}

/// The full definition of a Noise handshake with any pre-shared
/// ("pre-message") keys followed by the ordered sequence of handshake
/// messages.
/// 
/// Alternate between initiator and responder stating with the
/// initiator: `messages[0]` is sent by the initiator, `message[1]`
/// by the responder, etc.
#[derive(Copy, Clone)]
pub struct HandshakePattern {
    pre_messages_initiator: &'static [Token],
    pre_messages_responder: &'static [Token],
    messages: &'static [MessagePattern],
}

impl HandshakePattern {
    /// Returns `true` if this is a one-way pattern.
    pub const fn is_oneway(&self) -> bool {
        self.messages.len() == 1
    }

    /// Returns the ordered sequence of handshake messages.
    pub const fn messages(&self) -> &'static [MessagePattern] {
        self.messages
    }

    /// Returns the pre-message tokens known by the initiator
    /// before the handshake begins.
    pub const fn initiator_pre_messages(&self) -> &[Token] {
        self.pre_messages_initiator
    }

    /// Returns the pre-message tokens known by the responder
    /// before the handshake begins
    pub const fn responder_pre_messages(&self) -> &[Token] {
        self.pre_messages_responder
    }

    /// Returns `true` if any message in this pattern mixes in
    /// a pre-shared key ([`Token::PSK`])
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

    /// Returns `true` if the peer's static key is known as a
    /// pre-message from the perspective of `is_initiator`.
    pub const fn peer_static_is_premessage(&self, is_initiator: bool) -> bool {
        let peer_pre = if is_initiator {
            self.pre_messages_responder
        } else {
            self.pre_messages_initiator
        };
        Self::contains_s(peer_pre)
    }

    /// Returns `true` if the peer's ephemeral key is known as a
    /// pre-message from the perspective of `is_initiator`.
    pub const fn peer_ephemeral_is_premessage(&self, is_initiator: bool) -> bool {
        let peer_pre = if is_initiator {
            self.pre_messages_responder
        } else {
            self.pre_messages_initiator
        };
        Self::contains_e(peer_pre)
    }

    /// Returns `true` if this pattern/role requires a local static key
    /// as a pre-message or the message sends `Token::S` in one of its own
    /// message.
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

    /// Returns `true` if this pattern/role requires a local ephemeral key
    /// as a pre-message or the message sends `Token::S` in one of its own
    /// message.
    /// 
    /// # Note
    /// 
    /// Unlike [`local_static_required`](Self::local_static_required),
    /// only checks pre-messages and always returns `false` otherwise.
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

/// Trait that determines the properties of a Noise handshake
/// pattern (ex: `N`, `NN`, `XX`, etc.)
pub trait Pattern: Copy + 'static {
    /// The Noise protocol name for this pattern. Used when 
    /// building the string for the pattern.
    const NAME: &'static str;
    /// The pre-message and message sequence defining the pattern.
    const HANDSHAKE: HandshakePattern;
}

/// The `N` pattern: one-way handshake where the initiator sends a 
/// single message to a responder whose static key is known in advance.
/// 
/// See [NoiseExplorer: N](https://noiseexplorer.com/patterns/N/).
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

/// The `K` pattern: a one-way handshake where both parties static
/// keys are known to each other in advance.
/// 
/// See [NoiseExplorer: K](https://noiseexplorer.com/patterns/K).
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

/// The `X` pattern: a one-way handshake where the responder's static
/// key is known in advance and the initiator transmits its own static
/// key within the message.
/// 
/// See [NoiseExplorer: X](https://noiseexplorer.com/patterns/X).
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

/// The `NN` pattern: neither party's static key is known in advance
/// or transmitted.
/// 
/// See [NoiseExplorer: NN](https://noiseexplorer.com/patterns/NN).
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

/// The `NK` pattern: the responder's static key is known to the
/// initiator in advance, the initiator is not authenticated.
/// 
/// See [NoiseExplorer: NK](https://noiseexplorer.com/patterns/NK).
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

/// The `NX` pattern: the responder transmits its static key during
/// the handshake.
/// 
/// See [NoiseExplorer: NX](https://noiseexplorer.com/patterns/NX).
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

/// The `XN` pattern: the initiator's static key is transmitted
/// during the handshake, the responder is unauthenticated.
/// 
/// See [NoiseExplorer: XN](https://noiseexplorer.com/patterns/XN)
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

/// The `XK` pattern: the responder's static key is known in advance,
/// the initiator sends his during the handshake.
/// 
/// See [NoiseExplorer: XK](https://noiseexplorer.com/patterns/XK).
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

/// The `XX` pattern: neither party's static key is known in advance,
/// both send them during the handshake.
/// 
/// See [NoiseExplorer: XX](https://noiseexplorer.com/patterns/XX).
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

/// The `KN` pattern: The initiator's static key is known in advance,
/// the responder is not authenticated.
/// 
/// See [NoiseExplorer: KN](https://noiseexplorer.com/patterns/KN).
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

/// The `KK` pattern: both party's static keys are known to each
/// other in advance.
/// 
/// See [NoiseExplorer: KK](https://noiseexplorer.com/patterns/KK).
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

/// The `KX` pattern: The initiator's static key is known in advance,
/// the responder send his during the handshake.
/// 
/// See [NoiseExplorer: KX](https://noiseexplorer.com/patterns/KX).
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

/// The `IN` pattern: the initiator sends his static key in the first
/// message, the responder is not authenticated.
/// 
/// See [NoiseExplorer: IN](https://noiseexplorer.com/patterns/IN).
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

/// The `IK` pattern: the responder's static key is known in advance,
/// the initiator send his in the first message.
/// 
/// See [NoiseExplorer: IK](https://noiseexplorer.com/patterns/IK).
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

/// The `IX` pattern: neither static keys are known in advance,
/// the initiator sends his in the first message and the responder
/// in his response.
/// 
/// See [NoiseExplorer: IX](https://noiseexplorer.com/patterns/IX).
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

/// The `Npsk0` pattern: the `N` pattern with a pre-shared key mixed
/// in at the start of the message.
/// 
/// See [NoiseExplorer: Npsk0](https://noiseexplorer.com/patterns/Npsk0).
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

/// The `Kpsk0` pattern: the `K` pattern with a pre-shard key mixed 
/// in at the start of the message.
/// 
/// See [NoiseExplorer: Kpsk0](https://noiseexplorer.com/patterns/Kpsk0).
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

/// The `Xpsk1` pattern: the `X` pattern with a pre-shared key mixed
/// in at the end of the message.
/// 
/// See [NoiseExplorer: Xpsk1](https://noiseexplorer.com/patterns/Xpsk1).
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

/// The `NNpsk0` pattern: the `NN` pattern with a pre-shared key mixed
/// in at the start of the first message.
/// 
/// See [NoiseExplorer: NNpsk0](https://noiseexplorer.com/patterns/NNpsk0).
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

/// The `NNpsk2` pattern: the `NN` pattern with a pre-shared key mixed
/// in at the end of the second message.
///
/// See [NoiseExplorer: NNpsk2](https://noiseexplorer.com/patterns/NNpsk2).
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

/// The `NKpsk0` pattern: the `NK` pattern with a pre-shared key
/// mixed in at the start of the first message.
/// 
/// See [NoiseExplorer: NKpsk0](https://noiseexplorer.com/patterns/NKpsk0).
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

/// The `NKpsk2` pattern: the `NK` pattern with a pre-shared key mixed
/// in at the end of the second message.
/// 
/// See [NoiseExplorer: NKpsk2](https://noiseexplorer.com/patterns/NKpsk2).
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

/// The `NXpsk2` pattern: the `NX` pattern with a pre-shared key mixed
/// in at the end of the second message.
/// 
/// See [NoiseExplorer: NXpsk2](https://noiseexplorer.com/patterns/NXpsk2).
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

/// The `XNpsk3` pattern: the `XN` pattern with a pre-shared key mixed
/// in at the end of the third message.
/// 
/// See [NoiseExplorer: XNpsk3](https://noiseexplorer.com/patterns/XNpsk3).
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

/// The `XKpsk3` pattern: the `XK` pattern with a pre-shared key mixed
/// in at the end of the third message.
/// 
/// See [NoiseExplorer: XKpsk3](https://noiseexplorer.com/patterns/XKpsk3).
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

/// The `XXpsk3` pattern: the `XX` pattern with a pre-shared key mixed
/// in at the end of the third message.
/// 
/// See [NoiseExplorer: XXpsk3](https://noiseexplorer.com/patterns/XXpsk3).
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

/// The `KNpsk0` pattern: the `KN` pattern with a pre-shared key mixed
/// in at the start of the first message.
/// 
/// See [NoiseExplorer: KNpsk0](https://noiseexplorer.com/patterns/KNpsk0).
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

/// The `KNpsk2` pattern: the `KN` pattern with a pre-shared key mixed
/// in at the end of the second message.
/// 
/// See [NoiseExplorer: KNpsk2](https://noiseexplorer.com/patterns/KNpsk2).
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

/// The `KKpsk0` pattern: the `KK` pattern with a pre-shared key mixed
/// in at the end of the second message.
/// 
/// See [NoiseExplorer: KKpsk0](https://noiseexplorer.com/patterns/KKpsk0).
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

/// The `KKpsk2` pattern: the `KK` pattern with a pre-shared key mixed
/// in at the end of the second message.
/// 
/// See [NoiseExplorer: KKpsk2](https://noiseexplorer.com/patterns/KKpsk2).
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

/// The `KXpsk2` pattern: the `KX` pattern with a pre-shared key mixed
/// in at the end of the second message.
/// 
/// See [NoiseExplorer: KXpsk2](https://noiseexplorer.com/patterns/KXpsk2).
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

/// The `INpsk1` pattern: the `IN` pattern with a pre-shared key mixed
/// in at the end of the first message.
/// 
/// See [NoiseExplorer: INpsk1](https://noiseexplorer.com/patterns/INpsk1).
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

/// The `INpsk2` pattern: the `IN` pattern with a pre-shared key mixed
/// in at the end of the second message.
/// 
/// See [NoiseExplorer: INpsk2](https://noiseexplorer.com/patterns/INpsk2).
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

/// The `IKpsk1` pattern: the `IK` pattern with a pre-shared key mixed
/// in at the end of the first message.
/// 
/// See [NoiseExplorer: IKpsk1](https://noiseexplorer.com/patterns/IKpsk1).
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

/// The `IKpsk2` pattern: the `IK` pattern with a pre-shared key mixed
/// in at the end of the second message.
/// 
/// See [NoiseExplorer: IKpsk2](https://noiseexplorer.com/patterns/IKpsk2).
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

/// The `IXpsk2` pattern: the `IX` pattern with a pre-shared key mixed
/// in at the end of the second message.
/// 
/// See [NoiseExplorer: IXpsk2](https://noiseexplorer.com/patterns/IXpsk2).
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