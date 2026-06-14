package grade

import "github.com/dalf/cryptcheck-backend/internal/state"

var statusGrades = map[state.Level]string{
	state.Critical: "G",
	state.Error:    "F",
	state.Warning:  "E",
	state.Good:     "C",
	state.Great:    "B",
	state.Best:     "A",
}

func Calculate(valid, trusted bool, states state.Map) string {
	if !valid {
		return "V"
	}
	if !trusted {
		return "T"
	}

	levelStates := make(map[state.Level]interface{}, len(state.All))
	for _, level := range state.All {
		levelStates[level] = state.LevelState(states, level)
	}

	for _, level := range state.Bads {
		if active, ok := levelStates[level].(bool); ok && active {
			return statusGrades[level]
		}
	}

	current := "D"
	for _, level := range state.Goods {
		switch levelStates[level] {
		case false:
			return current
		case "some":
			return statusGrades[level]
		case "all":
			current = statusGrades[level] + "+"
		}
	}
	return current
}
