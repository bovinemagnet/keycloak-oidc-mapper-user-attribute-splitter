package com.sup.keycloak.oidc.mapper;

import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;

public class UserAttributeSplitterMapper extends AbstractOIDCProtocolMapper
		implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

	private static final Logger LOGGER = Logger.getLogger(UserAttributeSplitterMapper.class);

	public static final int MIN_ATTRIBUTE_NUM = 1;

	public static final
	String PROVIDER_ID = "oidc-usermodel-splitter-attribute-mapper";
	public static final String DISPLAY_TYPE = "User Attribute Splitter";
	public static final String HELP_TEXT = "User Attribute Splitter";

	// Split Token
	public static final String SPLIT_TOKEN = "split-token";
	public static final String SPLIT_TOKEN_LABEL = "Split Token";
	public static final String SPLIT_TOKEN_HELP_TEXT = "The string to split the user attribute on. EG: an @ will split an email address into user and domain.";

	// Multivalued
	public static final String MULTIVALUED = "split-multivalued";
	public static final String MULTIVALUED_LABEL = "Multivalued";
	public static final String MULTIVALUED_HELP_TEXT = "If the splitter matches multiple, send all though the token (otherwise send the first value";

	// Use final value
	public static final String FINAL_VALUE = "split-final-value";
	public static final String FINAL_VALUE_LABEL = "Final Value";
	public static final String FINAL_VALUE_HELP_TEXT = "By default, the first value is returned, this will return the final value.";

	// Skip if no match
	public static final String SKIP_MISSMATCH = "split-skip-missmatch";
	public static final String SKIP_MISSMATCH_LABEL = "Ignore Missmatch";
	public static final String SKIP_MISSMATCH_HELP_TEXT = "Ignore the attribute, if it cannot be split, by the splitter value. ie if you want to split by X and there is no X in the then TRUE: skip value, FALSE: add the full value";

	private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();
	static {
		ProviderConfigProperty property;
		property = new ProviderConfigProperty();
		property.setName(ProtocolMapperUtils.USER_ATTRIBUTE);
		property.setLabel(ProtocolMapperUtils.USER_MODEL_ATTRIBUTE_LABEL);
		property.setHelpText(ProtocolMapperUtils.USER_MODEL_ATTRIBUTE_HELP_TEXT);
		property.setType(ProviderConfigProperty.STRING_TYPE);
		configProperties.add(property);
		OIDCAttributeMapperHelper.addAttributeConfig(configProperties, UserAttributeMapper.class);

		// Split Token
		property = new ProviderConfigProperty();
		property.setName(SPLIT_TOKEN);
		property.setLabel(SPLIT_TOKEN_LABEL);
		property.setHelpText(SPLIT_TOKEN_HELP_TEXT);
		property.setType(ProviderConfigProperty.STRING_TYPE);
		configProperties.add(property);

		// Multivalued
		property = new ProviderConfigProperty();
		property.setName(MULTIVALUED);
		property.setLabel(MULTIVALUED_LABEL);
		property.setHelpText(MULTIVALUED_HELP_TEXT);
		property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
		configProperties.add(property);

		// Get First Value
		property = new ProviderConfigProperty();
		property.setName(FINAL_VALUE);
		property.setLabel(FINAL_VALUE_LABEL);
		property.setHelpText(FINAL_VALUE_HELP_TEXT);
		property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
		configProperties.add(property);

		// Skip if missmatch
		property = new ProviderConfigProperty();
		property.setName(SKIP_MISSMATCH);
		property.setLabel(SKIP_MISSMATCH_LABEL);
		property.setHelpText(SKIP_MISSMATCH_HELP_TEXT);
		property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
		configProperties.add(property);
	}

	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayType() {
		return DISPLAY_TYPE;
	}

	@Override
	public String getDisplayCategory() {
		return TOKEN_MAPPER_CATEGORY;
	}

	@Override
	public String getHelpText() {
		return "Map a custom user attribute to a token claim.";
	}

	@SuppressWarnings("PMD.DataflowAnomalyAnalysis")
	protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession) {

		UserModel user = userSession.getUser();
		final String attributeName = mappingModel.getConfig().get(ProtocolMapperUtils.USER_ATTRIBUTE);
		final boolean aggregateAttrs = Boolean.valueOf(mappingModel.getConfig().get(ProtocolMapperUtils.AGGREGATE_ATTRS));
		// Get the attribute value from the user attributes.
		Collection<String> attributeValue = KeycloakModelUtils.resolveAttribute(user, attributeName, aggregateAttrs);
		if (attributeValue == null) {
			LOGGER.info("setClaim attributeValue is null for name="+attributeName);
			return;
		}
		String splitToken = mappingModel.getConfig().get(SPLIT_TOKEN);
		// if the splitToken is null. No point trying to process.
		if (splitToken == null || splitToken.isEmpty()) {
			// then we do the default behaviour.
			LOGGER.info("[setClaim] splitToken is null for name="+attributeName);
			OIDCAttributeMapperHelper.mapClaim(token, mappingModel, attributeValue);
			return;
		}

		// get the first or last value.
		final boolean finalValue = Boolean.valueOf(mappingModel.getConfig().get(FINAL_VALUE));
		final boolean skipMissmatch = Boolean.valueOf(mappingModel.getConfig().get(SKIP_MISSMATCH));
		// If there is only one attributeValue then we just split based on the
		// split_token
		if (attributeValue.size() == MIN_ATTRIBUTE_NUM) {
			LOGGER.info("[setClaim] attributeValue.size() == 1");

			// We don't need to check if it is null, we did this before.
			if (splitToken != null) {
				String value = attributeValue.iterator().next();
				String convertedValue = splitValue(value, splitToken, finalValue, skipMissmatch);
				if (convertedValue != null)
				{
					OIDCAttributeMapperHelper.mapClaim(token, mappingModel, convertedValue);
					return;
				}
			}
			return;
		}
		LOGGER.info("[setClaim] splitToken is null for name="+attributeName);

		// we can assume there is more than one.

		ArrayList<String> values = new ArrayList<String>();
		// for each value in the string, split it and add it to the token.
		for (String value : attributeValue) {
			if (value.contains(splitToken)) {
				String[] split = value.split(splitToken);
				if (finalValue) {
					values.add(split[split.length - 1]);
				} else {
					values.add(split[0]);
				}
			} else {
				// if there is no split, just send what is matched.
				if (!skipMissmatch) {
					values.add(value);
				}
				//else {
					// we are skipping the missmatched case, and returning nothing.
					// we don't add anything.
				//}
			}
		}
		// if we have some values to return in the token, then map it.
		if (!values.isEmpty()) {
			OIDCAttributeMapperHelper.mapClaim(token, mappingModel, values);
		} else {
			// if there is no values then we don't map anything.
			return;
		}
	}

	public static ProtocolMapperModel createClaimMapper(String name,
			String userAttribute,
			String tokenClaimName, String claimType,
			boolean accessToken, boolean idToken, boolean multivalued) {
		return createClaimMapper(name, userAttribute, tokenClaimName, claimType,
				accessToken, idToken, multivalued, false);
	}

	public static ProtocolMapperModel createClaimMapper(String name,
			String userAttribute,
			String tokenClaimName, String claimType,
			boolean accessToken, boolean idToken,
			boolean multivalued, boolean aggregateAttrs) {
		ProtocolMapperModel mapper = OIDCAttributeMapperHelper.createClaimMapper(name, userAttribute,
				tokenClaimName, claimType,
				accessToken, idToken,
				PROVIDER_ID);

		if (multivalued) {
			mapper.getConfig().put(ProtocolMapperUtils.MULTIVALUED, "true");
		}
		if (aggregateAttrs) {
			mapper.getConfig().put(ProtocolMapperUtils.AGGREGATE_ATTRS, "true");
		}

		return mapper;
	}

	/**
	 * Return a list of values for adding to the token.
	 *
	 * @param attributeValue
	 * @param splitToken
	 * @param finalValue
	 * @param skipMissmatch
	 * @return
	 */
	public static final ArrayList<String> splitValues(Collection<String> attributeValue, String splitToken,
			boolean finalValue, boolean skipMissmatch) {

		ArrayList<String> values = new ArrayList<String>();
		// for each value in the string, split it and add it to the token.
		for (String value : attributeValue) {
				String valueReturned = splitValue(value, splitToken, finalValue, skipMissmatch);
				if (valueReturned != null && !valueReturned.isEmpty() && !valueReturned.trim().isEmpty()) {
					values.add(valueReturned);
				}
		}
		return values;
	}

	/**
	 * This method will split a string based on the values passed in.
	 *
	 * @param value The value to split.
	 * @param splitToken     The token to split on.
	 * @param finalValue     If true then the last value is returned. If false then
	 *                       the first value is returned.  When there is only one value, then it is returned.
	 * @param skipMissmatch  If true then we don't map anything if there is a
	 *                       missmatch. ie, don't return anything. If false then when it does not match we return the value that was passed in.
	 * @return A value match, or `null` if there are no matches. If the value is
	 *         null then we don't map anything.
	 */

	@SuppressWarnings({"PMD.DataflowAnomalyAnalysis", "PMD.AssignmentInOperand"})
	public static final String splitValue(final String value, final String splitToken, final boolean finalValue, final boolean skipMissmatch) {
		// Return null because the input value is null.
		// NOTE Space might be a valid value. so it is not || value.trim().isEmpty()
		if (value == null || value.isEmpty()) {
			LOGGER.debug("[splitValue] value is null or empty");
			return null;
		}
		// If the split token is null, then there is nothing to split
		// NOTE: Space might be a valid split token, so it is not trimmed.
		if (splitToken == null || splitToken.isEmpty()) {
			// if there is no split, just send what is matched.
			LOGGER.debug("[splitValue] splitToken is null or empty");
			if (!skipMissmatch) {
				return (value != null && !value.isEmpty()) ? value : null;
			} else {
				// we are skipping the miss-matched case, and returning nothing.
				// we don't add anything.
				return (value != null && !value.isEmpty()) ? value : null;
			}
		}
		// We can process the value, so we try to split it.
		try {
			String[] split;
			// if it has at least one split, we can continue.
			if ((split = value.split(splitToken)).length >= MIN_ATTRIBUTE_NUM) {
				if (finalValue) {
					String returnValue = split[split.length - 1];
					return (returnValue != null && !returnValue.isEmpty()) ? returnValue : null;
				} else {
					String returnValue = split[0];
					return (returnValue != null && !returnValue.isEmpty()) ? returnValue : null;
				}
			} else {
				if (split.length == MIN_ATTRIBUTE_NUM)
				{
					LOGGER.debug("value=: "+ value + "  split=" + split[0]);
					if (!finalValue) {
						LOGGER.trace("Length 1: " + split[0]);
						return split[0];
					}
					else
					{
						// There is no final value, so return null.
						return null;
					}
				}

				// if there is no split, just send what is matched.
				if (!skipMissmatch) {
					return (value != null && value.isEmpty()) ? value : null;
				} else {
					// we are skipping the missmatched case, and returning nothing.
					// we don't add anything.
					return null;
				}
			}
		} catch (java.util.regex.PatternSyntaxException ex) {
			// if there is an error, then we don't map anything.
			// Log the warning to the app server as an error message.
			LOGGER.warn("[splitValue] - Split Token Cannot Compile in OIDC Mapper. splitToken=" + splitToken);
			if (!skipMissmatch) {
				return (value != null && !value.isEmpty()) ? value : null;
			} else {
				// we are skipping the missmatched case, and returning nothing.
				// we don't add anything.
				return null;
			}
		}
	}

}
