from noise.constants import TOKEN_S, TOKEN_E, TOKEN_ES, TOKEN_SS, TOKEN_EE, TOKEN_SE
from noise.functions.patterns import OneWayPattern, Pattern


# One-way patterns

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
