module Yesod.ReCAPTCHA.Class
     ( YesodReCAPTCHA(..)
     , fakeField
     ) where

import Control.Applicative
import qualified Data.Text as T
import qualified Network.HTTP.Client.Conduit as HC
import qualified Yesod.Core as YC
import qualified Yesod.Form.Types as YF

-- | Class used by @yesod-recaptcha@'s fields.  It should be
-- fairly easy to implement a barebones instance of this class
-- for your foundation data type:
--
-- > instance YesodReCAPTCHA MyType where
-- >   recaptchaPublicKey  = return "[your public key]"
-- >   recaptchaPrivateKey = return "[your private key]"
--
-- > instance RenderMessage App ReCAPTCHAMessage where
-- >   renderMessage _ _ = englishReCAPTCHAMessage
--
-- You may also write a more sophisticated instance.  For
-- example, you may get these values from your @settings.yml@
-- instead of hardcoding them. Or you may give different keys
-- depending on the request (maybe you're serving to two
-- different domains in the same application).
--
-- /Minimum complete definition:/ 'recaptchaPublicKey' and
-- 'recaptchaPrivateKey'.
class HC.HasHttpManager site => YesodReCAPTCHA site where
    -- | Your reCAPTCHA public key.
    recaptchaPublicKey  :: YC.HandlerT site IO T.Text
    -- | Your reCAPTCHA private key.
    recaptchaPrivateKey :: YC.HandlerT site IO T.Text
    -- | A backdoor to the reCAPTCHA mechanism.  While doing
    -- automated tests you may need to fill a form that is
    -- protected by a CAPTCHA.  The whole point of using a
    -- CAPTCHA is disallowing access to non-humans, which
    -- hopefully your test suite is.
    --
    -- In order to solve this problem, you may define
    --
    -- > insecureRecaptchaBackdoor = return (Just "<secret CAPTCHA>")
    --
    -- Now, whenever someone fills @\<secret CAPTCHA\>@ as the
    -- CAPTCHA, the @yesod-recaptcha@ library will /not/ contact
    -- reCAPTCHA's servers and instead will blindly accept the
    -- secret CAPTCHA.
    --
    -- Note that this is a *huge* security hole in the wrong
    -- hands.  We /do not/ recommend using this function on a
    -- production environment without a good reason.  If for
    -- whatever reason you must use this function on a production
    -- environment, please make use of its access to 'GHandler'
    -- in order to return @Just@ only when strictly necessary.
    -- For example, you may return @Just@ only when the request
    -- comes from @localhost@ and read its contents from a secret
    -- file accessible only by SSH which is afterwards removed.
    --
    -- By default, this function returns @Nothing@, which
    -- completely disables the backdoor.
    insecureRecaptchaBackdoor :: YC.HandlerT site IO (Maybe T.Text)
    insecureRecaptchaBackdoor = return Nothing



-- | A fake field.  Just returns the value of a field.
fakeField :: T.Text -- ^ Field id.
          -> YF.MForm (YC.HandlerT site IO) (Maybe T.Text)
fakeField fid = (<|>) <$> YC.lookupGetParam fid <*> YC.lookupPostParam fid
