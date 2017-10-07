from typing import List

from .constants import TOKEN_E, TOKEN_S, TOKEN_EE, TOKEN_ES, TOKEN_SE, TOKEN_SS, TOKEN_PSK


class Pattern(object):
    """
    TODO document
    """
    def __init__(self):
        # As per specification, if both parties have pre-messages, the initiator is listed first. To reduce complexity,
        # pre_messages shall be a list of two lists:
        # the first for the initiator's pre-messages, the second for the responder
        self.pre_messages = [
            [],
            []
        ]

        # List of lists of valid tokens, alternating between tokens for initiator and responder
        self.tokens = []

        self.name = ''
        self.one_way = False
        self.psk_count = 0

    def has_pre_messages(self):
        return any(map(lambda x: len(x) > 0, self.pre_messages))

    def get_initiator_pre_messages(self) -> list:
        return self.pre_messages[0].copy()

    def get_responder_pre_messages(self) -> list:
        return self.pre_messages[1].copy()

    def apply_pattern_modifiers(self, modifiers: List[str]) -> None:
        # Applies given pattern modifiers to self.tokens of the Pattern instance.
        for modifier in modifiers:
            if modifier.startswith('psk'):
                try:
                    index = int(modifier.replace('psk', '', 1))
                except ValueError:
                    raise ValueError('Improper psk modifier {}'.format(modifier))

                if index // 2 > len(self.tokens):
                    raise ValueError('Modifier {} cannot be applied - pattern has not enough messages'.format(modifier))

                # Add TOKEN_PSK in the correct place in the correct message
                if index == 0:  # if 0, insert at the beginning of first message
                    self.tokens[0].insert(0, TOKEN_PSK)
                else:  # if bigger than zero, append at the end of first, second etc.
                    self.tokens[index - 1].append(TOKEN_PSK)
                self.psk_count += 1

            elif modifier == 'fallback':
                raise NotImplementedError  # TODO implement

            else:
                raise ValueError('Unknown pattern modifier {}'.format(modifier))

    def get_required_keypairs(self, initiator: bool) -> list:
        required = []
        if initiator:
            if self.name[0] in ('K', 'X', 'I'):
                required.append('s')
            if self.one_way or self.name[1] == 'K':
                required.append('rs')
        else:
            if self.name[0] == 'K':
                required.append('rs')
            if self.one_way or self.name[1] in ['K', 'X']:
                required.append('s')
        return required


# One-way patterns

class OneWayPattern(Pattern):
    def __init__(self):
        super(OneWayPattern, self).__init__()
        self.one_way = True


class PatternN(OneWayPattern):
    def __init__(self):
        super(PatternN, self).__init__()
        self.name = 'N'

        self.pre_messages = [
            [],
            [TOKEN_S]
        ]
        self.tokens = [
            [TOKEN_E, TOKEN_ES]
        ]


class PatternK(OneWayPattern):
    def __init__(self):
        super(PatternK, self).__init__()
        self.name = 'K'

        self.pre_messages = [
            [TOKEN_S],
            [TOKEN_S]
        ]
        self.tokens = [
            [TOKEN_E, TOKEN_ES, TOKEN_SS]
        ]


class PatternX(OneWayPattern):
    def __init__(self):
        super(PatternX, self).__init__()
        self.name = 'X'

        self.pre_messages = [
            [],
            [TOKEN_S]
        ]
        self.tokens = [
            [TOKEN_E, TOKEN_ES, TOKEN_S, TOKEN_SS]
        ]


# Interactive patterns

class PatternNN(Pattern):
    def __init__(self):
        super(PatternNN, self).__init__()
        self.name = 'NN'

        self.tokens = [
            [TOKEN_E],
            [TOKEN_E, TOKEN_EE]
        ]


class PatternKN(Pattern):
    def __init__(self):
        super(PatternKN, self).__init__()
        self.name = 'KN'

        self.pre_messages = [
            [TOKEN_S],
            []
        ]
        self.tokens = [
            [TOKEN_E],
            [TOKEN_E, TOKEN_EE, TOKEN_SE]
        ]


class PatternNK(Pattern):
    def __init__(self):
        super(PatternNK, self).__init__()
        self.name = 'NK'

        self.pre_messages = [
            [],
            [TOKEN_S]
        ]
        self.tokens = [
            [TOKEN_E, TOKEN_ES],
            [TOKEN_E, TOKEN_EE]
        ]


class PatternKK(Pattern):
    def __init__(self):
        super(PatternKK, self).__init__()
        self.name = 'KK'

        self.pre_messages = [
            [TOKEN_S],
            [TOKEN_S]
        ]
        self.tokens = [
            [TOKEN_E, TOKEN_ES, TOKEN_SS],
            [TOKEN_E, TOKEN_EE, TOKEN_SE]
        ]


class PatternNX(Pattern):
    def __init__(self):
        super(PatternNX, self).__init__()
        self.name = 'NX'

        self.tokens = [
            [TOKEN_E],
            [TOKEN_E, TOKEN_EE, TOKEN_S, TOKEN_ES]
        ]


class PatternKX(Pattern):
    def __init__(self):
        super(PatternKX, self).__init__()
        self.name = 'KX'

        self.pre_messages = [
            [TOKEN_S],
            []
        ]
        self.tokens = [
            [TOKEN_E],
            [TOKEN_E, TOKEN_EE, TOKEN_SE, TOKEN_S, TOKEN_ES]
        ]


class PatternXN(Pattern):
    def __init__(self):
        super(PatternXN, self).__init__()
        self.name = 'XN'

        self.tokens = [
            [TOKEN_E],
            [TOKEN_E, TOKEN_EE],
            [TOKEN_S, TOKEN_SE]
        ]


class PatternIN(Pattern):
    def __init__(self):
        super(PatternIN, self).__init__()
        self.name = 'IN'

        self.tokens = [
            [TOKEN_E, TOKEN_S],
            [TOKEN_E, TOKEN_EE, TOKEN_SE]
        ]


class PatternXK(Pattern):
    def __init__(self):
        super(PatternXK, self).__init__()
        self.name = 'XK'

        self.pre_messages = [
            [],
            [TOKEN_S]
        ]
        self.tokens = [
            [TOKEN_E, TOKEN_ES],
            [TOKEN_E, TOKEN_EE],
            [TOKEN_S, TOKEN_SE]
        ]


class PatternIK(Pattern):
    def __init__(self):
        super(PatternIK, self).__init__()
        self.name = 'IK'

        self.pre_messages = [
            [],
            [TOKEN_S]
        ]
        self.tokens = [
            [TOKEN_E, TOKEN_ES, TOKEN_S, TOKEN_SS],
            [TOKEN_E, TOKEN_EE, TOKEN_SE]
        ]


class PatternXX(Pattern):
    def __init__(self):
        super(PatternXX, self).__init__()
        self.name = 'XX'

        self.tokens = [
            [TOKEN_E],
            [TOKEN_E, TOKEN_EE, TOKEN_S, TOKEN_ES],
            [TOKEN_S, TOKEN_SE]
        ]


class PatternIX(Pattern):
    def __init__(self):
        super(PatternIX, self).__init__()
        self.name = 'IX'

        self.tokens = [
            [TOKEN_E, TOKEN_S],
            [TOKEN_E, TOKEN_EE, TOKEN_SE, TOKEN_S, TOKEN_ES]
        ]


patterns_map = {
    'PatternN': PatternN,
    'PatternK': PatternK,
    'PatternX': PatternX,
    'PatternNN': PatternNN,
    'PatternKN': PatternKN,
    'PatternNK': PatternNK,
    'PatternKK': PatternKK,
    'PatternNX': PatternNX,
    'PatternKX': PatternKX,
    'PatternXN': PatternXN,
    'PatternIN': PatternIN,
    'PatternXK': PatternXK,
    'PatternIK': PatternIK,
    'PatternXX': PatternXX,
    'PatternIX': PatternIX,
}
