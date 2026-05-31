
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

TEST(test_user, valid_user_with_z) {
  ASSERT_EQ(PWM_OK, pwm_is_valid_user("abcz"));
}

TEST(test_user, min_length_valid) {
  ASSERT_EQ(PWM_OK, pwm_is_valid_user("abcd"));
}

TEST(test_user, too_short) {
  ASSERT_EQ(PWM_INVALID_USER_ID, pwm_is_valid_user("abc"));
}

TEST(test_user, too_long) {
  ASSERT_EQ(PWM_INVALID_USER_ID, pwm_is_valid_user("abcdefghijk"));
}

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
