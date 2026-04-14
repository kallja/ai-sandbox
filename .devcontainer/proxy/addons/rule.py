class FinalizedRule:
    def __init__(self, conditions, action):
        self._conditions = conditions
        self._action = action

    def evaluate(self, flow) -> str | None:
        if all(c(flow) for c in self._conditions):
            return self._action
        return None


class MatchMode:
    def __init__(self, getter, conditions, comparator):
        self._getter = getter
        self._conditions = conditions
        self._comparator = comparator

    def __call__(self, value) -> "Rule":
        return self.one_of([value])

    def one_of(self, values) -> "Rule":
        vs = [v.lower() for v in values]
        return Rule(
            self._conditions
            + [lambda flow, vs=vs: any(self._comparator(self._getter(flow), v) for v in vs)],
        )


class ExactField:
    def __init__(self, getter, conditions):
        self._getter = getter
        self._conditions = conditions

    def one_of(self, values) -> "Rule":
        vs = {v.lower() for v in values}
        return Rule(
            self._conditions
            + [lambda flow, vs=vs, g=self._getter: g(flow) in vs],
        )

    def __call__(self, value) -> "Rule":
        return self.one_of([value])


class StringField(ExactField):
    @property
    def starts_with(self) -> MatchMode:
        return MatchMode(self._getter, self._conditions, str.startswith)


class Rule:
    def __init__(self, conditions=None):
        self._conditions = list(conditions or [])

    @property
    def method(self) -> ExactField:
        return ExactField(lambda flow: flow.request.method.lower(), self._conditions)

    @property
    def path(self) -> StringField:
        return StringField(lambda flow: flow.request.path.lower(), self._conditions)

    def __call__(self, action) -> FinalizedRule:
        return self.then(action)

    def then(self, action) -> FinalizedRule:
        return FinalizedRule(self._conditions, action)


rule = Rule()
