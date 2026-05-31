
#include <pwm.h>
#include <gtest/gtest.h>


TEST(test_pass, invalid_pass_length5) {
  ASSERT_EQ(PWM_INVALID_PASSWORD, pwm_is_valid_password("Aa9zx"));
}

TEST(test_pass, valid_pass_length6) {
  ASSERT_EQ(PWM_OK, pwm_is_valid_password("Aa9za1"));
}

TEST(test_pass, invvalid_pass_with_two_punct) {
  ASSERT_EQ(PWM_INVALID_PASSWORD, pwm_is_valid_password("Aa9za1!!"));
}

TEST(test_pass, blacklisted_pass1) {
  ASSERT_EQ(PWM_INVALID_PASSWORD, pwm_is_valid_password("A123zad!"));
}
// etc ...

// Test maximum length 12 is valid
TEST(test_pass, valid_pass_length12) {
  ASSERT_EQ(PWM_OK, pwm_is_valid_password("Aa9za1bcde12"));
}

// Test 13 chars is rejected (above maximum)
TEST(test_pass, too_long_pass) {
  ASSERT_EQ(PWM_INVALID_PASSWORD, pwm_is_valid_password("Aa9za1bcde123"));
}

// Test no lowercase is rejected
TEST(test_pass, no_lowercase) {
  ASSERT_EQ(PWM_INVALID_PASSWORD, pwm_is_valid_password("AA9ZA1!"));
}

// Test no uppercase is rejected
TEST(test_pass, no_uppercase) {
  ASSERT_EQ(PWM_INVALID_PASSWORD, pwm_is_valid_password("aa9za1."));
}

// Test no digit is rejected
TEST(test_pass, no_digit) {
  ASSERT_EQ(PWM_INVALID_PASSWORD, pwm_is_valid_password("AaZzAa."));
}

// Test that exactly one punctuation is valid
TEST(test_pass, one_punct_valid) {
  ASSERT_EQ(PWM_OK, pwm_is_valid_password("Aa9za1!"));
}

// Test zero punctuation is also valid
TEST(test_pass, no_punct_valid) {
  ASSERT_EQ(PWM_OK, pwm_is_valid_password("Aa9za11"));
}

// Test another blacklisted word
TEST(test_pass, blacklisted_pass2) {
  ASSERT_EQ(PWM_INVALID_PASSWORD, pwm_is_valid_password("Aabcdef1"));
}

// Test an invalid character (e.g., space)
TEST(test_pass, invalid_char_space) {
  ASSERT_EQ(PWM_INVALID_PASSWORD, pwm_is_valid_password("Aa9 za1"));
}

TEST(test_pass, invalid_char_above_z) {
    ASSERT_EQ(PWM_INVALID_PASSWORD, pwm_is_valid_password("Aa9za1{"));
}


int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
