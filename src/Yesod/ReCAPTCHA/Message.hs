module Yesod.ReCAPTCHA.Message
     ( ReCAPTCHAMessage(..)
     , englishReCAPTCHAMessage
     ) where

import Data.Monoid ((<>))
import qualified Data.Text as T

data ReCAPTCHAMessage = RCMsgEmptyCaptcha
                      | RCMsgInvalidCaptcha
                      | RCMsgReCaptchaUnreachable
                      | RCMsgOtherError T.Text
  deriving (Show, Eq, Read)

englishReCAPTCHAMessage :: ReCAPTCHAMessage -> T.Text
englishReCAPTCHAMessage RCMsgEmptyCaptcha         = "Captcha is empty"
englishReCAPTCHAMessage RCMsgInvalidCaptcha       = "Invalid captcha"
englishReCAPTCHAMessage RCMsgReCaptchaUnreachable = "Can not connect to ReCAPTCHA. Please, try later."
englishReCAPTCHAMessage (RCMsgOtherError msg)     = "Error occured: " <> msg
