class FinalizedRule:
    def __init__(self, conditions, action):
        self._conditions = conditions
        self._action = action

    def evaluate(self, flow) -> str | None:
        if all(c(flow) for c in self._conditions):
            return self._action
        return None


class Rule:
    def __init__(self, conditions=None):
        self._conditions = list(conditions or [])

    def method_one_of(self, methods):
        methods_upper = {m.upper() for m in methods}
        return Rule(
            self._conditions + [lambda flow, m=methods_upper: flow.request.method in m],
        )

    def path_starts_with(self, *prefixes):
        return Rule(
            self._conditions
            + [lambda flow, p=prefixes: any(flow.request.path.startswith(px) for px in p)],
        )

    def __call__(self, action) -> FinalizedRule:
        return self.then(action)

    def then(self, action) -> FinalizedRule:
        return FinalizedRule(self._conditions, action)


rule = Rule()
