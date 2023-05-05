package com.sup.keycloak.oidc.mapper;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.FullNameMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

public class UserAttributeSplitterMapperTest {

	static final String CLAIM_NAME = "handlerIdClaimNameExample";

	static final String TEST_NAME  = "{displayName}:{index} => expectedResult={0}, userAttribString={1}, splitToken={2}, finalValue={3}, skipMissmatch={4}";

	@Test
	public void shouldTokenMapperDisplayCategory() {
		final String tokenMapperDisplayCategory = new FullNameMapper().getDisplayCategory();
		assertThat(new UserAttributeSplitterMapper().getDisplayCategory()).isEqualTo(tokenMapperDisplayCategory);
	}

	@Test
	public void shouldHaveDisplayType() {
		assertThat(new UserAttributeSplitterMapper().getDisplayType()).isNotBlank();
	}

	@Test
	public void shouldHaveHelpText() {
		assertThat(new UserAttributeSplitterMapper().getHelpText()).isNotBlank();
	}

	@Test
	public void shouldHaveIdId() {
		assertThat(new UserAttributeSplitterMapper().getId()).isNotBlank();
	}

	@Test
	@DisplayName("shouldHavePropertiesInConfiguration")
	public void shouldHaveProperties() {
		final List<String> configPropertyNames = new UserAttributeSplitterMapper().getConfigProperties().stream()
				.map(ProviderConfigProperty::getName)
				.collect(Collectors.toList());
		assertThat(configPropertyNames).contains(
				OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME,
				OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO,
				UserAttributeSplitterMapper.SPLIT_TOKEN,
				UserAttributeSplitterMapper.FINAL_VALUE,
				UserAttributeSplitterMapper.SKIP_MISSMATCH);
	}

	@Test
	@Disabled
	public void shouldAddClaim() {
		final UserSessionModel session = givenUserSession();

		final AccessToken accessToken = transformAccessToken(session);

		assertThat(accessToken.getOtherClaims().get(CLAIM_NAME)).isEqualTo("hello world");
	}

	private UserSessionModel givenUserSession() {
		UserSessionModel userSession = Mockito.mock(UserSessionModel.class);
		UserModel user = Mockito.mock(UserModel.class);
		when(userSession.getUser()).thenReturn(user);
		return userSession;
	}

	private AccessToken transformAccessToken(UserSessionModel userSessionModel) {
		final ProtocolMapperModel mappingModel = new ProtocolMapperModel();
		mappingModel.setConfig(createConfig());
		return new UserAttributeSplitterMapper().transformAccessToken(new AccessToken(), mappingModel, null,
				userSessionModel,
				null);
	}

	private Map<String, String> createConfig() {
		final Map<String, String> result = new HashMap<>();
		result.put("access.token.claim", "true");
		result.put("claim.name", CLAIM_NAME);
		result.put("user.attribute", "Test");

		return result;
	}

	@DisplayName("Test combination of single values with @ symbol")
	@ParameterizedTest(name = TEST_NAME)
	@CsvSource({
			"paul,paul@test-email.com.au,@, false,false",
			"test-email.com.au,paul@test-email.com.au,@, true,false",
			"paul,paul@test-email.com.au,@, false,true",
			"test-email.com.au,paul@test-email.com.au,@, true,true",
			"null_mc_Nullingtontest-email.com.au,null_mc_Nullingtontest-email.com.au,@, false,false",
			"null_mc_Nullingtontest-email.com.au,null_mc_Nullingtontest-email.com.au,@, true,false",
			"null_mc_Nullingtontest-email.com.au,null_mc_Nullingtontest-email.com.au,@, false,true",
			"null_mc_Nullingtontest-email.com.au,null_mc_Nullingtontest-email.com.au,@, true,true",
			"paul,paul@test-email@com@au,@, false,false",
			"au,paul@test-email@com@au,@, true,false"
	})
	public void splitValueTest(String result, String userAttribString, String splitToken, final boolean finalValue,
			boolean skipMissmatch) {
		assertThat(UserAttributeSplitterMapper.splitValue(userAttribString, splitToken, finalValue, skipMissmatch))
				.isEqualTo(result);
	}

	@DisplayName("Test combination of single values")
	@ParameterizedTest(name =TEST_NAME)
	@CsvSource({
			"paul,paul@test-email.com.au,@, false,false",
			"test-email.com.au,paul@test-email.com.au,@, true,false",
			"paul,paul@test-email.com.au,@, false,true",
			"test-email.com.au,paul@test-email.com.au,@, true,true",
			"null_mc_Nullingtontest-email.com.au,null_mc_Nullingtontest-email.com.au,@, false,false",
			"null_mc_Nullingtontest-email.com.au,null_mc_Nullingtontest-email.com.au,@, true,false",
			"null_mc_Nullingtontest-email.com.au,null_mc_Nullingtontest-email.com.au,@, false,true",
			"null_mc_Nullingtontest-email.com.au,null_mc_Nullingtontest-email.com.au,@, true,true",
			"paul,paul@test-email@com@au,@, false,false",
			"au,paul@test-email@com@au,@, true,false"
	})
	public void splitValuesTest(String result, String userAttribString, String splitToken, final boolean finalValue,
			boolean skipMissmatch) {
		assertThat(UserAttributeSplitterMapper.splitValue(userAttribString, splitToken, finalValue, skipMissmatch))
				.isEqualTo(result);
	}

	@DisplayName("Test contains")
	@ParameterizedTest(name = "{displayName}:{index} => value={0}, contains={1}, splitToken={2}")
	@CsvSource({
			"ZZ_APPLES,ZZ_APPLES",
			"ZZ_APPLES,ZZ_",
			"ZZ_APPLES,ZZ"

	})
	public void testContains(String value, String contains) {
		//assertThat( "ZZ_APPLES".contains("ZZ_"));
		//assertThat( "ZZ_APPLES".contains("ZZ"));
		//assertThat( "ZZ_APPLES".contains("ZZ_APPLES"));
		assertThat(value.contains(contains));

	}

	@DisplayName("First Letter Drop Test")
	@ParameterizedTest(name = TEST_NAME)
	//return, value, splitString, finalValue, skipMissmatch
	@CsvSource({
			"123456,123456,S, true,true",
			"123456,123456,S, true,false",
			"123456,123456,S, false,true",
			"123456,123456,S, false,false",
			",S123456,S, false,false",
			",S123456,S, false,true",
			"123456,S123456,S, true,false",
			"123456,S123456,S, true,true",
			"123456,S123456,(?i)s,true,true",
			"123456,s123456,(?i)s,true,true",
			"123456,S123456,(?i)S,true,true",
			"123456,s123456,(?i)S,true,true",
			"123456,s123456,[sS],true,true",
			"123456,S123456,[sS],true,true",
			"A123456,A123456,[sS],true,true",
			",,[sS],true,true",
	})
	public void splitValuesLetterTest(String result, String userAttribString, String splitToken, final boolean finalValue,
			boolean skipMissmatch) {
		assertThat(UserAttributeSplitterMapper.splitValue(userAttribString, splitToken, finalValue, skipMissmatch))
				.isEqualTo(result);
	}

	@DisplayName("VALID: Letter Split: Middle")
	@ParameterizedTest(name = TEST_NAME)
	//return value, value, splitString, finalValue, skipMissmatch
	@CsvSource({
		"456,123S456,S, true,true",
		"456,123S456,S, true,false",
		"123,123S456,S, false,true",
		"123,123S456,S, false,false",
		"456,123S456,[Ss], true,true",
		"456,123S456,[Ss], true,false",
		"123,123S456,[Ss], false,true",
		"123,123S456,[Ss], false,false",
		"456,123S456,(?i)s, true,true",
		"456,123S456,(?i)s, true,false",
		"123,123S456,(?i)s, false,true",
		"123,123S456,(?i)s, false,false",
		"456,123S456,(?i)S, true,true",
		"456,123S456,(?i)S, true,false",
		"123,123S456,(?i)S, false,true",
		"123,123S456,(?i)S, false,false"
	})
	public void splitValuesMidLetterTest(String result, String userAttribString, String splitToken, final boolean finalValue,
			boolean skipMissmatch) {
		assertThat(UserAttributeSplitterMapper.splitValue(userAttribString, splitToken, finalValue, skipMissmatch))
				.isEqualTo(result);
	}



	@DisplayName("Test NULL Values")
	@ParameterizedTest(name = TEST_NAME)
	@CsvSource({
	"ABCD,ABCD,,true,true",
	"ABCD,ABCD,,false,true",
	"ABCD,ABCD,,true,false",
	"ABCD,ABCD,,false,false",
	",,,true,true",
	",,,false,true",
	",,,true,false",
	",,,false,false"
})
	public void splitValuesNullChecksTest(String result, String userAttribString, String splitToken, final boolean finalValue,
	boolean skipMissmatch) {
assertThat(UserAttributeSplitterMapper.splitValue(userAttribString, splitToken, finalValue, skipMissmatch))
		.isEqualTo(result);
}


	@DisplayName("VALID: Letter Split: END")
	@ParameterizedTest(name =TEST_NAME)
	//return value, value, splitString, finalValue, skipMissmatch
	@CsvSource({
		"123456,123456S,S, true,true",
		"123456,123456S,S, true,false",
		"123456,123456S,S, false,true",
		"123456,123456S,S, false,false",
		"123456,123456S,[Ss], true,true",
		"123456,123456S,[Ss], true,false",
		"123456,123456S,[Ss], false,true",
		"123456,123456S,[Ss], false,false",
		"123456,123456S,(?i)s, true,true",
		"123456,123456S,(?i)s, true,false",
		"123456,123456S,(?i)s, false,true",
		"123456,123456S,(?i)s, false,false",
		"123456,123456S,(?i)S, true,true",
		"123456,123456S,(?i)S, true,false",
		"123456,123456S,(?i)S, false,true",
		"123456,123456S,(?i)S, false,false"
	})
	public void splitValuesEndLetterTest(String result, String userAttribString, String splitToken, final boolean finalValue,
			boolean skipMissmatch) {
		assertThat(UserAttributeSplitterMapper.splitValue(userAttribString, splitToken, finalValue, skipMissmatch))
				.isEqualTo(result);
	}


	@DisplayName("VALID: Letter Split: Multi")
	@ParameterizedTest(name =TEST_NAME)
	//return value, value, splitString, finalValue, skipMissmatch
	@CsvSource({
		"333,111S222S333,S, true,true",
		"333,111S222S333,S, true,false",
		"111,111S222S333,S, false,true",
		"111,111S222S333,S, false,false",
	})
	public void splitValuesMultiLetterTest(String result, String userAttribString, String splitToken, final boolean finalValue,
			boolean skipMissmatch) {
		assertThat(UserAttributeSplitterMapper.splitValue(userAttribString, splitToken, finalValue, skipMissmatch))
				.isEqualTo(result);
	}


	@DisplayName("VALID: Letter Split: Invalid Regex")
	@ParameterizedTest(name = TEST_NAME)
	//return value, value, splitString, finalValue, skipMissmatch
	@CsvSource({
		",1234567,[a-zA-Z0-9,\\.\'], true,true",
		"1234567,1234567,^^(&*), true,true",
		"1234567,1234567,^^(&*), true,false",
		"1234567,1234567,^^(&*), false,true",
		"1234567,1234567,^^(&*), false,false"
	})
	public void splitValuesInvalidRegexTest(String result, String userAttribString, String splitToken, final boolean finalValue,
			boolean skipMissmatch) {
		assertThat(UserAttributeSplitterMapper.splitValue(userAttribString, splitToken, finalValue, skipMissmatch))
				.isEqualTo(result);
	}

	/**
	 * Remember a split will always return the input string, when no expression is found.
	 * @param splitLength
	 * @param inputString
	 * @param splitToken
	 */
	@DisplayName("SPLITTER:")
	@ParameterizedTest(name = "{displayName}:{index} => splitLength={0}, inputString={1}, splitToken={2}")
	@CsvSource({
		"1,ABCD,S",
		"2,ABSCD,S",
		"2,SABCD,S",
		"1,ABCDS,S",  // Note this case.
		"2,SABCDS,S", // Note This case.
		"3,ASBSCD,S",
		"4,ASBSCSD,S"
	})
	public void splitFunctionalityTest(int splitLength, String inputString, String splitToken) {
		assertThat(inputString.split(splitToken)).hasSize(splitLength);
	}



	/**
	 * This tests a client example of a student id, split on S where the first
	 * letter is or is not an `S`, and thus it will get the number.
	 * @param result it is expecting.
	 * @param userAttribString what is passed in
	 * @param splitToken what it is split on.
	 * @param finalValue Whether to return the final value of not.
	 * @param skipMissmatch Whether to skip the missmatch or not. if miss match = true, then don't return anything.
	 */
	@DisplayName("Client Test: First Letter Drop Test")
	@ParameterizedTest(name = TEST_NAME)
	//return, value, splitString, finalValue, skipMissmatch
	@CsvSource({
			"123456,123456,[Ss], true,true",
			"123456,123456,[Ss], true,false",
			"123456,123456,[Ss], false,true",
			"123456,123456,[Ss], false,false",
			",S123456,[Ss], false,false", // TYhere is no first value before the s
			",S123456,[Ss], false,true",  // TYhere is no first value before the s
			"123456,S123456,[Ss], true,false",
			"123456,s123456,[Ss], true,false",
			"123456,S123456,[Ss], true,true",
			"123456,s123456,[Ss], true,true"
	})
	public void dropSLetterTest(String result, String userAttribString, String splitToken, final boolean finalValue,
			boolean skipMissmatch) {
		assertThat(UserAttributeSplitterMapper.splitValue(userAttribString, splitToken, finalValue, skipMissmatch))
				.isEqualTo(result);
	}


	@Test
	@SuppressWarnings({"PMD.AvoidDuplicateLiterals"})
	public void dropMultiLetterTest() {
		// Array List of Strings
		List<String> initialList = new ArrayList<>();
		initialList.add("123456");
		initialList.add("s123456");
		initialList.add("S123456");
		initialList.add("123456s");
		initialList.add("123456S");

		assertThat(UserAttributeSplitterMapper.splitValues(initialList, "[Ss]", true, true)).containsExactly("123456", "123456", "123456", "123456", "123456");

	}


}
