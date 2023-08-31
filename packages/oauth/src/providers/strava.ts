import {
	OAuth2ProviderAuth,
	createOAuth2AuthorizationUrl,
	validateOAuth2AuthorizationCode
} from "../core/oauth2.js";
import { ProviderUserAuth } from "../core/provider.js";
import { handleRequest, authorizationHeader } from "../utils/request.js";

import type { Auth } from "lucia";

type Config = {
	clientId: string;
	clientSecret: string;
	scope?: string[];
	redirectUri?: string;
};

const PROVIDER_ID = "strava";

export const strava = <_Auth extends Auth = Auth>(
	auth: _Auth,
	config: Config
): StravaAuth<_Auth> => {
	return new StravaAuth(auth, config);
};

export class StravaAuth<_Auth extends Auth = Auth> extends OAuth2ProviderAuth<
	StravaAuth<_Auth>
> {
	private config: Config;

	constructor(auth: _Auth, config: Config) {
		super(auth);

		this.config = config;
	}

	public getAuthorizationUrl = async (): Promise<
		readonly [url: URL, state: string]
	> => {
		return await createOAuth2AuthorizationUrl(
			"https://www.strava.com/oauth/authorize",
			{
				clientId: this.config.clientId,
				scope: this.config.scope ?? [],
				redirectUri: this.config.redirectUri
			}
		);
	};

	public validateCallback = async (
		code: string
	): Promise<StravaUserAuth<_Auth>> => {
		const stravaTokens = await this.validateAuthorizationCode(code);
		const stravaUser = await getStravaUser(stravaTokens.accessToken);
		return new StravaUserAuth(this.auth, stravaUser, stravaTokens);
	};

	private validateAuthorizationCode = async (
		code: string
	): Promise<StravaTokens> => {
		const tokens =
			await validateOAuth2AuthorizationCode<AccessTokenResponseBody>(
				code,
				"https://www.strava.com/oauth/token",
				{
					clientId: this.config.clientId,
					clientPassword: {
						clientSecret: this.config.clientSecret,
						authenticateWith: "client_secret"
					}
				}
			);
		if ("refresh_token" in tokens) {
			return {
				accessToken: tokens.access_token,
				accessTokenExpiresIn: tokens.expires_in,
				refreshToken: tokens.refresh_token,
				refreshTokenExpiresIn: tokens.refresh_token_expires_in
			};
		}
		return {
			accessToken: tokens.access_token,
			accessTokenExpiresIn: null
		};
	};
}

const getStravaUser = async (accessToken: string): Promise<StravaUser> => {
	const stravaUserRequest = new Request("https://www.strava.com/api/v3/athlete", {
		headers: {
			Authorization: authorizationHeader("bearer", accessToken)
		}
	});
	return await handleRequest<StravaUser>(stravaUserRequest);
};

export class StravaUserAuth<
	_Auth extends Auth
> extends ProviderUserAuth<_Auth> {
	public stravaTokens: StravaTokens;
	public stravaUser: StravaUser;

	constructor(auth: _Auth, stravaUser: StravaUser, stravaTokens: StravaTokens) {
		super(auth, PROVIDER_ID, stravaUser.id.toString());

		this.stravaTokens = stravaTokens;
		this.stravaUser = stravaUser;
	}
}

type AccessTokenResponseBody =
	| {
			access_token: string;
	  }
	| {
			access_token: string;
			refresh_token: string;
			expires_in: number;
			refresh_token_expires_in: number;
	  };

export type StravaTokens =
	| {
			accessToken: string;
			accessTokenExpiresIn: null;
	  }
	| {
			accessToken: string;
			accessTokenExpiresIn: number;
			refreshToken: string;
			refreshTokenExpiresIn: number;
	  };

export type StravaUser = {
  id: number;
  username: string;
  resource_state: number;
  firstname: string;
  lastname: string;
  city: string;
  state: string;
  country: string;
  sex: string;
  premium: boolean;
  created_at: string;
  updated_at: string;
  badge_type_id: number;
  profile_medium: string;
  profile: string;
  friend?: boolean;
  follower?: boolean;
  follower_count: number;
  friend_count: number;
  mutual_friend_count: number;
  athlete_type: number;
  data_preference: "string";
  measurement_preference: string;
  clubs: string[];
  ftp?: number;
  weight: number;
  bikes: Gear[];
  shoes: Gear[];
};

type Gear = {
  id: string;
  primary: boolean;
  name: string;
  resource_state: number;
  distance: number;
}
