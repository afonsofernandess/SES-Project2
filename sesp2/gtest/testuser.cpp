
#include <pwm.h>
#include <gtest/gtest.h>


TEST(test_user, short_length) {
  ASSERT_EQ(PWM_INVALID_USER_ID, pwm_is_valid_user("rui"));
}

TEST(test_user, invalid_char) {
  ASSERT_EQ(PWM_INVALID_USER_ID, pwm_is_valid_user("@rui"));
}

TEST(test_user, valid_user) {
  ASSERT_EQ(PWM_OK, pwm_is_valid_user("ruiruiruir"));
}

TEST(test_user, valid_user2) {
  ASSERT_EQ(PWM_OK, pwm_is_valid_user("ruiruirui"));
}

// etc ...

// Test that 'z' is valid (Bug  — <= vs <)
TEST(test_user, valid_user_with_z) {
  ASSERT_EQ(PWM_OK, pwm_is_valid_user("abcz"));
}

// Test that exactly 4 chars is valid (minimum boundary)
TEST(test_user, min_length_valid) {
  ASSERT_EQ(PWM_OK, pwm_is_valid_user("abcd"));
}

// Test that 3 chars is rejected (below minimum)
TEST(test_user, too_short) {
  ASSERT_EQ(PWM_INVALID_USER_ID, pwm_is_valid_user("abc"));
}

// Test that 11 chars is rejected (above maximum)
TEST(test_user, too_long) {
  ASSERT_EQ(PWM_INVALID_USER_ID, pwm_is_valid_user("abcdefghijk"));
}

// Test that uppercase letters in the middle are rejected
TEST(test_user, invalid_uppercase) {
  ASSERT_EQ(PWM_INVALID_USER_ID, pwm_is_valid_user("abcD"));
}

TEST(test_user, invalid_char_above_z) {
    ASSERT_EQ(PWM_INVALID_USER_ID, pwm_is_valid_user("abc{"));
} 

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
