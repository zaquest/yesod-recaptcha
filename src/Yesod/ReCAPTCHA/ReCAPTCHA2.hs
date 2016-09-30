{-# LANGUAGE QuasiQuotes #-} -- for hlint
module Yesod.ReCAPTCHA.ReCAPTCHA2
    ( YesodReCAPTCHA(..)
    , recaptchaAForm
    , recaptchaMForm
    ) where

import Data.Monoid ((<>))
import Control.Arrow (second)
import Yesod.Core (whamlet)
import qualified Control.Monad.Reader as MR
import qualified Control.Exception.Lifted as E
import qualified Control.Monad.Trans.Resource as R
import qualified Data.ByteString.Char8 as B8
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Network.HTTP.Conduit as H
import qualified Network.HTTP.Client.Conduit as HC
import qualified Network.Info as NI
import qualified Network.Socket as HS
import qualified Network.Wai as W
import qualified Network.Wai.Request as W (appearsSecure)
import qualified Yesod.Core as YC
import qualified Yesod.Form.Functions as YF
import qualified Yesod.Form.Types as YF
import Data.Aeson ((.:), (.:?))
import qualified Data.Aeson as DA
import qualified Data.Aeson.Types as DA
import Text.Blaze (toMarkup)
import Yesod.ReCAPTCHA.Class
import Yesod.ReCAPTCHA.Message

-- | A reCAPTCHA field.  This 'YF.AForm' returns @()@ because
-- CAPTCHAs give no useful information besides having being typed
-- correctly or not.  When the user does not type the CAPTCHA
-- correctly, this 'YF.AForm' will automatically fail in the same
-- way as any other @yesod-form@ widget fails, so you may just
-- ignore the @()@ value.
recaptchaAForm :: (YC.RenderMessage site ReCAPTCHAMessage
                  ,YesodReCAPTCHA site) => YF.AForm (YC.HandlerT site IO) ()
recaptchaAForm = YF.formToAForm $ second (:[]) <$> recaptchaMForm


-- | Same as 'recaptchaAForm', but instead of being an
-- 'YF.AForm', it's an 'YF.MForm'.
recaptchaMForm :: (YC.RenderMessage site ReCAPTCHAMessage
                  ,YesodReCAPTCHA site) =>
                  YF.MForm (YC.HandlerT site IO)
                           ( YF.FormResult ()
                           , YF.FieldView site )
recaptchaMForm = do
  responseField <- fakeField "g-recaptcha-response"
  ret <- maybe (return Nothing)
               (YC.lift . fmap Just . check)
               responseField
  app <- YC.getYesod
  (_, _, langs) <- MR.ask
  let (formRet, errs) = case ret of
                          Nothing        -> (YF.FormMissing,     Nothing)
                          Just Ok        -> (YF.FormSuccess (),  Nothing)
                          Just (Error e) -> let err = YC.renderMessage app langs e
                                            in (YF.FormFailure [err], Just (toMarkup err))
      formView = YF.FieldView
                   { YF.fvLabel    = ""
                   , YF.fvTooltip  = Nothing
                   , YF.fvId       = "g-recaptcha"
                   , YF.fvInput    = recaptchaWidget
                   , YF.fvErrors   = errs
                   , YF.fvRequired = True
                   }
  return (formRet, formView)


-- | Widget with reCAPTCHA's HTML.
recaptchaWidget :: YesodReCAPTCHA site => YC.WidgetT site IO ()
recaptchaWidget = do
  publicKey <- YC.handlerToWidget recaptchaPublicKey
  appearsSecure <- W.appearsSecure <$> YC.waiRequest
  let proto | appearsSecure = "https"
            | otherwise = "http" :: T.Text
  YC.addScriptRemote (proto <> "://www.google.com/recaptcha/api.js")
  [whamlet| <div .g-recaptcha data-sitekey=#{publicKey}> |]


-- | Contact reCAPTCHA servers and find out if the user correctly
-- guessed the CAPTCHA.  Unfortunately, reCAPTCHA doesn't seem to
-- provide an HTTPS endpoint for this API even though we need to
-- send our private key.
check :: YesodReCAPTCHA site =>
         T.Text -- ^ @recaptcha_response_field@
      -> YC.HandlerT site IO CheckRet
check "" = return $ Error RCMsgEmptyCaptcha
check response = do
  backdoor <- insecureRecaptchaBackdoor
  if Just response == backdoor
    then return Ok
    else do
      privateKey <- recaptchaPrivateKey
      sockaddr <- W.remoteHost <$> YC.waiRequest
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
      req <- H.parseUrl "https://www.google.com/recaptcha/api/siteverify"
      let query = [ ("secret", TE.encodeUtf8 privateKey)
                  , ("remoteip",   B8.pack       remoteip)
                  , ("response",   TE.encodeUtf8 response)
                  ]
      eresp <- E.try $ R.runResourceT $ H.httpLbs (H.urlEncodedBody query req) manager
      case H.responseBody <$> eresp of
        Right resp -> case DA.decode resp of
          Just (RecaptchaResponse True _) -> return Ok
          Just (RecaptchaResponse False (Just (why:_))) -> return $ Error (RCMsgOtherError why)
          _ -> do
            $(YC.logError) $ T.concat [ "Yesod.ReCAPTCHA: could not parse "
                                      , T.pack (show resp) ]
            return (Error RCMsgReCaptchaUnreachable)
        Left exc -> do
          $(YC.logError) $ T.concat [ "Yesod.ReCAPTCHA: could not contact server ("
                                    , T.pack (show (exc :: E.SomeException))
                                    , ")" ]
          return (Error RCMsgReCaptchaUnreachable)


-- | See 'check'.
data CheckRet = Ok | Error ReCAPTCHAMessage


data RecaptchaResponse = RecaptchaResponse Bool (Maybe [T.Text])
  deriving Show

instance DA.FromJSON RecaptchaResponse where
  parseJSON (DA.Object v) = RecaptchaResponse
                              <$> v .:  "success"
                              <*> v .:? "errors"
  parseJSON invalid = DA.typeMismatch "RecaptchaResponse" invalid
