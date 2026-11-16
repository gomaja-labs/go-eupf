package core

import "github.com/gomaja-labs/go-pfcp/ie"

// A decoded FAR update is shared by rule planning, End Marker selection and
// notification rearming. Each grouped view is built once per request.
type farUpdate struct {
	fields     *ie.UpdateFARFields
	forwarding *ie.UpdateForwardingParametersFields
	id         uint32
}

func decodeFARUpdate(value *ie.IE) (farUpdate, error) {
	fields, err := value.UpdateFAR()
	if err != nil {
		return farUpdate{}, err
	}
	id, err := fields.FARID.FARID()
	if err != nil {
		return farUpdate{}, err
	}
	result := farUpdate{fields: fields, id: id}
	if fields.UpdateForwardingParameters != nil {
		result.forwarding, err = fields.UpdateForwardingParameters.UpdateForwardingParameters()
		if err != nil {
			return farUpdate{}, &ruleFailure{ie.RuleIDTypeFAR, id, err}
		}
	}
	return result, nil
}
