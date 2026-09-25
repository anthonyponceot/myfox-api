import logging
from typing import Any
import voluptuous as vol
from collections.abc import Mapping

from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow, SOURCE_REAUTH, ConfigFlowResult
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import selector
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .crypto.secure import encode, decode

from .const import (DOMAIN_MYFOX,
                    CONFIG_VERSION,
                    PREFIX_ENTRY)
from .api.const import (KEY_SITE_ID,
                        KEY_TOKEN,
                        KEY_ACCESS_TOKEN,
                        KEY_REFRESH_TOKEN,
                        KEY_EXPIRE_IN,
                        KEY_EXPIRE_AT,
                        KEY_CLIENT_ID,
                        KEY_CLIENT_SECRET,
                        KEY_MYFOX_USER,
                        KEY_MYFOX_PSWD,
                        KEY_AUTH_IMPLEMENTATION,
                        KEY_CACHE_EXPIRE_IN,
                        CACHE_EXPIRE_IN,
                        POOLING_INTERVAL_DEF,
                        KEY_POOLING_INTERVAL,
                        KEY_CACHE_CAMERA,
                        CACHE_CAMERA,
                        KEY_CACHE_SECURITY,
                        CACHE_SECURITY,
                        KEY_USE_CODE_ALARM,
                        KEY_AUTHORIZED_CODE_ALARM,
                        KEY_NB_RETRY_DEFAULT,
                        KEY_NB_RETRY_CAMERA,
                        KEY_DELAY_BETWEEN_RETRY
                        )
from .api.myfoxapi_exception import (InvalidTokenMyFoxException, MyFoxException)

from .api import (
    MyFoxEntryDataApi,
    MyFoxOptionsDataApi
)
from .api.myfoxapi import (
    MyFoxApiClient
)
from .devices.site import MyFoxSite

_LOGGER = logging.getLogger(__name__)


class MyFoxOptionsFlowHandler(OptionsFlow):
    """ Options pour l'integration """
    def __init__(self) -> None:
        """ Initialize options flow. """
        self.siteId: int | None = None

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """ Manage the options. """
        if self.config_entry.entry_id is not None:
            self.siteId = self.config_entry.unique_id.replace(PREFIX_ENTRY, "", 1)
        options = self.config_entry.options
        if user_input is not None:
            if KEY_USE_CODE_ALARM not in user_input or not user_input.get(KEY_USE_CODE_ALARM):
                update_infos: dict[str, Any] = {}
                update_infos[KEY_USE_CODE_ALARM] = False
                update_infos[KEY_AUTHORIZED_CODE_ALARM] = ""
                user_input.update(update_infos)
            if KEY_AUTHORIZED_CODE_ALARM in user_input and len(user_input.get(KEY_AUTHORIZED_CODE_ALARM).strip()) > 0:
                update_infos: dict[str, Any] = {}
                update_infos[KEY_AUTHORIZED_CODE_ALARM] = encode(user_input.get(KEY_AUTHORIZED_CODE_ALARM).strip(), self.siteId)
                user_input.update(update_infos)
            else :
                update_infos : dict[str, Any] = {}
                update_infos[KEY_AUTHORIZED_CODE_ALARM] = ""
                user_input.update(update_infos)
            return self.async_create_entry(title="", data=user_input)

        cache_expire_in_param = CACHE_EXPIRE_IN
        if KEY_CACHE_EXPIRE_IN in options:
            cache_expire_in_param = int(options.get(KEY_CACHE_EXPIRE_IN))
        pooling_interval = POOLING_INTERVAL_DEF
        if KEY_POOLING_INTERVAL in options:
            pooling_interval = int(options.get(KEY_POOLING_INTERVAL))
        cache_camera = CACHE_CAMERA
        if KEY_CACHE_CAMERA in options:
            cache_camera = int(options.get(KEY_CACHE_CAMERA))
        cache_security = CACHE_SECURITY
        if KEY_CACHE_SECURITY in options:
            cache_security = int(options.get(KEY_CACHE_SECURITY))
        use_code_alarm = False
        if KEY_USE_CODE_ALARM in options:
            use_code_alarm = options.get(KEY_USE_CODE_ALARM)
        authorized_codes = ""
        if KEY_AUTHORIZED_CODE_ALARM in options and len(options.get(KEY_AUTHORIZED_CODE_ALARM).strip()) > 0:
            authorized_codes = decode(options.get(KEY_AUTHORIZED_CODE_ALARM), self.siteId)
        nb_retry_default = 5
        if KEY_NB_RETRY_DEFAULT in options:
            nb_retry_default = int(options.get(KEY_NB_RETRY_DEFAULT))
        nb_retry_camera = 2
        if KEY_NB_RETRY_CAMERA in options:
            nb_retry_camera = int(options.get(KEY_NB_RETRY_CAMERA))
        delay_between_retry = 30
        if KEY_DELAY_BETWEEN_RETRY in options:
            delay_between_retry = int(options.get(KEY_DELAY_BETWEEN_RETRY))

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        KEY_POOLING_INTERVAL,
                        default=pooling_interval,
                    ): int,
                    vol.Required(
                        KEY_CACHE_EXPIRE_IN,
                        default=cache_expire_in_param,
                    ): int,
                    vol.Required(
                        KEY_CACHE_CAMERA,
                        default=cache_camera,
                    ): int,
                    vol.Required(
                        KEY_CACHE_SECURITY,
                        default=cache_security,
                    ): int,
                    vol.Required(
                        KEY_NB_RETRY_DEFAULT,
                        default=nb_retry_default,
                    ): int,
                    vol.Required(
                        KEY_NB_RETRY_CAMERA,
                        default=nb_retry_camera,
                    ): int,
                    vol.Required(
                        KEY_DELAY_BETWEEN_RETRY,
                        default=delay_between_retry,
                    ): int,
                    vol.Optional(
                        KEY_USE_CODE_ALARM,
                        default=use_code_alarm,
                    ): bool,
                    vol.Optional(
                        KEY_AUTHORIZED_CODE_ALARM,
                        default=authorized_codes): TextSelector(
                        TextSelectorConfig(
                            type=TextSelectorType.PASSWORD
                        )
                    )
                }
            )
        )


class MyFoxConfigFlow(ConfigFlow, domain=DOMAIN_MYFOX):
    """Config flow based on client id, client secret, MyFox user and password."""
    DOMAIN = DOMAIN_MYFOX
    VERSION = CONFIG_VERSION

    def __init__(self) -> None:
        self.myfox_client: MyFoxApiClient | None = None
        self.siteId = None
        self.site: MyFoxSite | None = None
        self.sites: list[MyFoxSite] = []
        self.data: dict[str, Any] | None = None
        self._reauth_entry: ConfigEntry | None = None

    def _credential_schema(self) -> vol.Schema:
        """Formulaire CLIENT_ID, CLIENT_SECRET, MYFOX_USER, MYFOX_PSWD."""
        data = self.data or {}
        return vol.Schema(
            {
                vol.Required(KEY_CLIENT_ID, default=data.get(KEY_CLIENT_ID, "")): str,
                vol.Required(KEY_CLIENT_SECRET, default=data.get(KEY_CLIENT_SECRET, "")): TextSelector(
                    TextSelectorConfig(type=TextSelectorType.PASSWORD)
                ),
                vol.Required(KEY_MYFOX_USER, default=data.get(KEY_MYFOX_USER, "")): str,
                vol.Required(KEY_MYFOX_PSWD, default=data.get(KEY_MYFOX_PSWD, "")): TextSelector(
                    TextSelectorConfig(type=TextSelectorType.PASSWORD)
                ),
            }
        )

    def _store_login(self, user_input: dict[str, Any]) -> None:
        """Enregistre les identifiants et les tokens obtenus via grant password."""
        info = self.myfox_client.myfox_info
        self.data = {
            KEY_CLIENT_ID: user_input[KEY_CLIENT_ID],
            KEY_CLIENT_SECRET: user_input[KEY_CLIENT_SECRET],
            KEY_MYFOX_USER: user_input[KEY_MYFOX_USER],
            KEY_MYFOX_PSWD: user_input[KEY_MYFOX_PSWD],
            KEY_TOKEN: {
                KEY_ACCESS_TOKEN: info.access_token,
                KEY_REFRESH_TOKEN: info.refresh_token,
                KEY_EXPIRE_IN: info.expires_in,
                KEY_EXPIRE_AT: info.expires_time,
                "token_type": "Bearer",
            },
        }
        if self.siteId is not None:
            self.data[KEY_SITE_ID] = self.siteId
        self.sites = info.sites

    async def _async_login(self, user_input: dict[str, Any]) -> str | None:
        """Authentification password grant. Retourne une clef d'erreur ou None."""
        myfox_info = MyFoxEntryDataApi(
            client_id=user_input[KEY_CLIENT_ID],
            client_secret=user_input[KEY_CLIENT_SECRET],
            username=user_input[KEY_MYFOX_USER],
            password=user_input[KEY_MYFOX_PSWD],
        )
        options = MyFoxOptionsDataApi()
        options.cache_time = CACHE_EXPIRE_IN
        myfox_info.options = options
        self.myfox_client = MyFoxApiClient(myfox_info)
        try:
            login_ok = await self.myfox_client.login()
        except InvalidTokenMyFoxException:
            return "invalid_auth"
        except MyFoxException:
            _LOGGER.exception("Connexion MyFox impossible")
            return "cannot_connect"
        except Exception:
            _LOGGER.exception("Erreur inattendue pendant la connexion MyFox")
            return "unknown"
        if not login_ok:
            return "invalid_auth"
        if not self.myfox_client.myfox_info.sites:
            return "no_site"
        self._store_login(user_input)
        return None

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None):
        """Reconfigure an existing entry with the password grant."""
        if "entry_id" in self.context and self.context["entry_id"]:
            existing_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
            if existing_entry and self.data is None:
                self.data = existing_entry.data.copy()
                if KEY_SITE_ID in self.data:
                    self.siteId = self.data[KEY_SITE_ID]
        if self.data is None:
            self.data = {}
        return await self.async_step_user()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect CLIENT_ID, CLIENT_SECRET, MYFOX_USER and MYFOX_PSWD."""
        errors: dict[str, str] = {}
        if user_input is not None:
            error = await self._async_login(user_input)
            if error is None:
                if self.source == SOURCE_REAUTH and self._reauth_entry is not None:
                    data = self._reauth_entry.data.copy()
                    data.update(self.data)
                    data.pop(KEY_AUTH_IMPLEMENTATION, None)
                    return self.async_update_reload_and_abort(
                        self._reauth_entry,
                        data=data,
                    )
                return await self.async_step_select_site()
            errors["base"] = error

        return self.async_show_form(
            step_id="user",
            data_schema=self._credential_schema(),
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Ask again for the four credentials after an authentication error."""
        if KEY_SITE_ID in entry_data:
            self.siteId = entry_data[KEY_SITE_ID]
        self.data = dict(entry_data)
        if "entry_id" in self.context and self.context["entry_id"]:
            self._reauth_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm reauth dialog."""
        if user_input is None:
            return self.async_show_form(
                step_id="reauth_confirm",
                description_placeholders={"name": "MyFox"},
            )
        return await self.async_step_user()

    # Step de selection du site
    async def async_step_select_site(self, info: dict[str, Any] | None = None) -> FlowResult:
        """ Selection du site"""
        _LOGGER.debug("async_step_select_site :  %s", str(info))
        if info is not None:
            """ sauvegarde du site et de l'entry """
            for site in self.sites:
                if site.key == info.get(KEY_SITE_ID) :
                    self.site = site
            device_unique_id = PREFIX_ENTRY + str(self.site.siteId)

            existing_entry = await self.async_set_unique_id(device_unique_id, raise_on_progress=False)

            new_data = {
                KEY_SITE_ID: str(self.site.siteId),
            }
            if existing_entry:
                options = existing_entry.options.copy()
                self.data.update(info)
                self.data.update(new_data)

                if self.hass.config_entries.async_update_entry(existing_entry, data=self.data, options=options):
                    self.hass.config_entries.async_schedule_reload(existing_entry.entry_id)
                return self.async_abort(reason="updated_successfully")
            else :
                options = {
                    KEY_CACHE_EXPIRE_IN : CACHE_EXPIRE_IN
                }
                self.data.update(info)
                self.data.update(new_data)
                return self.async_create_entry(title=device_unique_id, data=self.data, options=options)

        site_list = list()
        default_site = None
        for site in self.sites:
            site_list.append(site.key)
            if self.siteId and int(self.siteId) == int(site.siteId) :
                default_site = site

        SITE_STEP_SCHEMA = vol.Schema({
            vol.Required(KEY_SITE_ID, default=default_site): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=site_list,
                    mode=selector.SelectSelectorMode.DROPDOWN
                )
            )
        })

        return self.async_show_form(
            step_id="select_site", data_schema=SITE_STEP_SCHEMA)

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: ConfigEntry,
    ) -> MyFoxOptionsFlowHandler:
        """ Create the options flow. """
        return MyFoxOptionsFlowHandler()
