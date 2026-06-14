package state

type Level string

const (
	Critical Level = "critical"
	Error    Level = "error"
	Warning  Level = "warning"
	Good     Level = "good"
	Great    Level = "great"
	Best     Level = "best"
)

var (
	Bads  = []Level{Critical, Error, Warning}
	Goods = []Level{Good, Great, Best}
	All   = append(append([]Level{}, Bads...), Goods...)
)

type Map map[Level]map[string]interface{}

func Empty() Map {
	m := make(Map, len(All))
	for _, level := range All {
		m[level] = map[string]interface{}{}
	}
	return m
}

type Check struct {
	Name   string
	Level  Level
	Result interface{} // bool or nil
}

type Checker interface {
	Checks() []Check
	Children() []Checker
}

func Collect(checker Checker) Map {
	checks := flattenChecks(checker)
	grouped := make(map[Level]map[string]interface{})
	for _, level := range All {
		grouped[level] = map[string]interface{}{}
	}

	byLevel := make(map[Level][]Check)
	for _, check := range checks {
		byLevel[check.Level] = append(byLevel[check.Level], check)
	}

	for level, levelChecks := range byLevel {
		byName := make(map[string][]interface{})
		for _, check := range levelChecks {
			byName[check.Name] = append(byName[check.Name], check.Result)
		}
		for name, results := range byName {
			grouped[level][name] = mergeResults(results)
		}
	}
	return grouped
}

func flattenChecks(checker Checker) []Check {
	out := append([]Check{}, checker.Checks()...)
	for _, child := range checker.Children() {
		out = append(out, flattenChecks(child)...)
	}
	return out
}

func mergeResults(results []interface{}) interface{} {
	hasTrue, hasFalse := false, false
	for _, result := range results {
		switch v := result.(type) {
		case bool:
			if v {
				hasTrue = true
			} else {
				hasFalse = true
			}
		case nil:
		default:
			if v == true {
				hasTrue = true
			} else if v == false {
				hasFalse = true
			}
		}
	}
	if hasTrue {
		return true
	}
	if hasFalse {
		return false
	}
	return nil
}

func LevelState(states Map, level Level) interface{} {
	values := make([]interface{}, 0, len(states[level]))
	for _, value := range states[level] {
		values = append(values, value)
	}
	return aggregateLevel(level, values)
}

func aggregateLevel(level Level, values []interface{}) interface{} {
	if isGood(level) {
		hasFalse, hasTrue := false, false
		for _, value := range values {
			switch v := value.(type) {
			case bool:
				if v {
					hasTrue = true
				} else {
					hasFalse = true
				}
			case nil:
			}
		}
		if hasFalse {
			if hasTrue {
				return "some"
			}
			return false
		}
		return "all"
	}

	for _, value := range values {
		if v, ok := value.(bool); ok && v {
			return true
		}
	}
	return false
}

func isGood(level Level) bool {
	switch level {
	case Good, Great, Best:
		return true
	default:
		return false
	}
}

// ExportJSON encodes states with null values preserved.
func ExportJSON(states Map) map[string]interface{} {
	out := make(map[string]interface{}, len(All))
	for _, level := range All {
		levelMap := states[level]
		if levelMap == nil {
			out[string(level)] = map[string]interface{}{}
			continue
		}
		encoded := make(map[string]interface{}, len(levelMap))
		for name, value := range levelMap {
			encoded[name] = value
		}
		out[string(level)] = encoded
	}
	return out
}
