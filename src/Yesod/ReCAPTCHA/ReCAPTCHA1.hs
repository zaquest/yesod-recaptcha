{-# LANGUAGE QuasiQuotes #-} -- for hlint
module Yesod.ReCAPTCHA.ReCAPTCHA1
    ( YesodReCAPTCHA(..)
    , recaptchaAForm
    , recaptchaMForm
    , recaptchaOptions
    , RecaptchaOptions(..)
    ) where

import Control.Arrow (second)
import Data.Typeable (Typeable)
import Yesod.Core (whamlet)
import qualified Control.Exception.Lifted as E
import qualified Control.Monad.Trans.Resource as R
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import qualified Data.Default as D
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Encoding.Error as TEE
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TLE
import qualified Network.HTTP.Conduit as H
import qualified Network.HTTP.Types as HT
import qualified Network.HTTP.Client.Conduit as HC
import qualified Network.Info as NI
import qualified Network.Socket as HS
import qualified Network.Wai as W
import qualified Network.Wai.Request as W (appearsSecure)
import qualified Yesod.Core as YC
import qualified Yesod.Form.Functions as YF
import qualified Yesod.Form.Types as YF
import Yesod.ReCAPTCHA.Class


-- | A reCAPTCHA field.  This 'YF.AForm' returns @()@ because
-- CAPTCHAs give no useful information besides having being typed
-- correctly or not.  When the user does not type the CAPTCHA
-- correctly, this 'YF.AForm' will automatically fail in the same
-- way as any other @yesod-form@ widget fails, so you may just
-- ignore the @()@ value.
recaptchaAForm :: YesodReCAPTCHA site => YF.AForm (YC.HandlerT site IO) ()
recaptchaAForm = YF.formToAForm $ second (:[]) <$> recaptchaMForm


-- | Same as 'recaptchaAForm', but instead of being an
-- 'YF.AForm', it's an 'YF.MForm'.
recaptchaMForm :: YesodReCAPTCHA site =>
                  YF.MForm (YC.HandlerT site IO)
                           ( YF.FormResult ()
                           , YF.FieldView site )
recaptchaMForm = do
  challengeField <- fakeField "recaptcha_challenge_field"
  responseField  <- fakeField "recaptcha_response_field"
  ret <- maybe (return Nothing)
               (YC.lift . fmap Just . uncurry check)
               ((,) <$> challengeField <*> responseField)
  let view = recaptchaWidget $ case ret of
                                 Just (Error err) -> Just err
                                 _                -> Nothing
      formRet = case ret of
                  Nothing        -> YF.FormMissing
                  Just Ok        -> YF.FormSuccess ()
                  Just (Error _) -> YF.FormFailure []
      formView = YF.FieldView
                   { YF.fvLabel    = ""
                   , YF.fvTooltip  = Nothing
                   , YF.fvId       = "recaptcha_challenge_field"
                   , YF.fvInput    = view
                   , YF.fvErrors   = Nothing
                   , YF.fvRequired = True
                   }
  return (formRet, formView)


-- | Widget with reCAPTCHA's HTML.
recaptchaWidget :: YesodReCAPTCHA site =>
                   Maybe T.Text -- ^ Error code, if any.
                -> YC.WidgetT site IO ()
recaptchaWidget merr = do
  publicKey <- YC.handlerToWidget recaptchaPublicKey
  appearsSecure <- W.appearsSecure <$> YC.waiRequest
  let proto | appearsSecure = "https"
            | otherwise = "http" :: T.Text
      err = maybe "" (T.append "&error=") merr
  [whamlet|
    <script src="#{proto}://www.google.com/recaptcha/api/challenge?k=#{publicKey}#{err}">
    <noscript>
       <iframe src="#{proto}://www.google.com/recaptcha/api/noscript?k=#{publicKey}#{err}"
           height="300" width="500" frameborder="0">
       <br>
       <textarea name="recaptcha_challenge_field" rows="3" cols="40">
       <input type="hidden" name="recaptcha_response_field" value="manual_challenge">
  |]


-- | Contact reCAPTCHA servers and find out if the user correctly
-- guessed the CAPTCHA.  Unfortunately, reCAPTCHA doesn't seem to
-- provide an HTTPS endpoint for this API even though we need to
-- send our private key.
check :: YesodReCAPTCHA site =>
         T.Text -- ^ @recaptcha_challenge_field@
      -> T.Text -- ^ @recaptcha_response_field@
      -> YC.HandlerT site IO CheckRet
check "" _ = return $ Error "invalid-request-cookie"
check _ "" = return $ Error "incorrect-captcha-sol"
check challenge response = do
  backdoor <- insecureRecaptchaBackdoor
  if Just response == backdoor
    then return Ok
    else do
      privateKey <- recaptchaPrivateKey
      sockaddr   <- W.remoteHost <$> YC.waiRequest
      remoteip <- case sockaddr of
                       HS.SockAddrInet _ hostAddr ->
                         return . show $ NI.IPv4 hostAddr
                       HS.SockAddrInet6 _ _ (w1, w2, w3, w4) _ ->
                         return . show $ NI.IPv6 w1 w2 w3 w4
                       _ -> do
                          $(YC.logError) $ "Yesod.ReCAPTCHA: Couldn't find out remote IP, \
                           \are you using a reverse proxy?  If yes, then \
                           \please file a bug report at \
                           \<https://github.com/meteficha/yesod-recaptcha>."
                          fail "Could not find remote IP address for reCAPTCHA."
      manager <- HC.getHttpManager <$> YC.getYesod
      let req = D.def
                  { H.method      = HT.methodPost
                  , H.host        = "www.google.com"
                  , H.path        = "/recaptcha/api/verify"
                  , H.queryString = HT.renderSimpleQuery False query
                  }
          query = [ ("privatekey", TE.encodeUtf8 privateKey)
                  , ("remoteip",   B8.pack       remoteip)
                  , ("challenge",  TE.encodeUtf8 challenge)
                  , ("response",   TE.encodeUtf8 response)
                  ]
      eresp <- E.try $ R.runResourceT $ H.httpLbs req manager
      case (L8.lines . H.responseBody) <$> eresp of
        Right ("true":_)      -> return Ok
        Right ("false":why:_) -> return . Error . TL.toStrict $
                                TLE.decodeUtf8With TEE.lenientDecode why
        Right other -> do
          $(YC.logError) $ T.concat [ "Yesod.ReCAPTCHA: could not parse "
                                    , T.pack (show other) ]
          return (Error "recaptcha-not-reachable")
        Left exc -> do
          $(YC.logError) $ T.concat [ "Yesod.ReCAPTCHA: could not contact server ("
                                    , T.pack (show (exc :: E.SomeException))
                                    , ")" ]
          return (Error "recaptcha-not-reachable")


-- | See 'check'.
data CheckRet = Ok | Error T.Text


-- | Define the given 'RecaptchaOptions' for all forms declared
-- after this widget.  This widget may be used anywhere, on the
-- @<head>@ or on the @<body>@.
--
-- Note that this is /not/ required to use 'recaptchaAForm' or
-- 'recaptchaMForm'.
recaptchaOptions :: YC.Yesod site =>
                    RecaptchaOptions
                 -> YC.WidgetT site IO ()
recaptchaOptions s | s == D.def = return ()
recaptchaOptions s =
  [whamlet|
    <script>
      var RecaptchaOptions = {
      $maybe t <- theme s
        theme : '#{t}',
      $maybe l <- lang s
        lang : '#{l}',
      x : 'x'
      };
  |]


-- | Options that may be given to reCAPTCHA.  In order to use
-- them on your site, use `recaptchaOptions` anywhere before the
-- form that contains the `recaptchaField`.
--
-- Note that there's an instance for 'D.Default', so you may use
-- 'D.def'.
data RecaptchaOptions =
  RecaptchaOptions {
      -- | Theme of the reCAPTCHA field.  Currently may be
      -- @\"red\"@, @\"white\"@, @\"blackglass\"@ or @\"clean\"@.
      -- A value of @Nothing@ uses the default.
      theme :: Maybe T.Text

      -- | Language.
    , lang :: Maybe T.Text
    }
  deriving (Eq, Ord, Show, Typeable)

-- | Allows you to use 'D.def' and get sane default values.
instance D.Default RecaptchaOptions where
    def = RecaptchaOptions Nothing Nothing
