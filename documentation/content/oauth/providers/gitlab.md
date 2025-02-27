---
title: "Gitlab"
description: "Learn how to use the Gitlab OAuth provider"
---

OAuth integration for Gitlab. Provider id is `gitlab`.

```ts
import { gitlab } from "@lucia-auth/oauth/providers";
import { auth } from "./lucia.js";

const gitlabAuth = gitlab(auth, configs);
```

## `gitlab()`

Scope `read_user` is always included.

```ts
const gitlab: (
	auth: Auth,
	configs: {
		clientId: string;
		clientSecret: string;
		redirectUri: string;
		scope?: string[];
	}
) => GitlabProvider;
```

##### Parameters

| name                   | type                                       | description                    | optional |
| ---------------------- | ------------------------------------------ | ------------------------------ | :------: |
| `auth`                 | [`Auth`](/reference/lucia/interfaces/auth) | Lucia instance                 |          |
| `configs.clientId`     | `string`                                   | Gitlab OAuth app client id     |          |
| `configs.clientSecret` | `string`                                   | Gitlab OAuth app client secret |          |
| `configs.redirectUri`  | `string`                                   | an authorized redirect URI     |          |
| `configs.scope`        | `string[]`                                 | an array of scopes             |    ✓     |

##### Returns

| type                                | description     |
| ----------------------------------- | --------------- |
| [`GitlabProvider`](#gitlabprovider) | Gitlab provider |

## Interfaces

### `GitlabAuth`

See [`OAuth2ProviderAuth`](/reference/oauth/interfaces/oauth2providerauth).

```ts
// implements OAuth2ProviderAuth<GitlabAuth<_Auth>>
interface GitlabAuth<_Auth extends Auth> {
	getAuthorizationUrl: () => Promise<readonly [url: URL, state: string]>;
	validateCallback: (code: string) => Promise<GitlabUserAuth<_Auth>>;
}
```

| type                                |
| ----------------------------------- |
| [`GitlabUserAuth`](#gitlabuserauth) |

##### Generics

| name    | extends                                    | default |
| ------- | ------------------------------------------ | ------- |
| `_Auth` | [`Auth`](/reference/lucia/interfaces/auth) | `Auth`  |

### `GitlabTokens`

```ts
type GitlabTokens = {
	accessToken: string;
	accessTokenExpiresIn: number;
	refreshToken: string;
};
```

### `GitlabUser`

```ts
type GitlabUser = {
	id: number;
	username: string;
	email: string;
	name: string;
	state: string;
	avatar_url: string;
	web_url: string;
	created_at: string;
	bio: string;
	public_email: string;
	skype: string;
	linkedin: string;
	twitter: string;
	discord: string;
	website_url: string;
	organization: string;
	job_title: string;
	pronouns: string;
	bot: boolean;
	work_information: string | null;
	followers: number;
	following: number;
	local_time: string;
	last_sign_in_at: string;
	confirmed_at: string;
	theme_id: number;
	last_activity_on: string;
	color_scheme_id: number;
	projects_limit: number;
	current_sign_in_at: string;
	identities: { provider: string; extern_uid: string }[];
	can_create_group: boolean;
	can_create_project: boolean;
	two_factor_enabled: boolean;
	external: boolean;
	private_profile: boolean;
	commit_email: string;
};
```

### `GitlabUserAuth`

Extends [`ProviderUserAuth`](/reference/oauth/interfaces/provideruserauth).

```ts
interface Auth0UserAuth<_Auth extends Auth> extends ProviderUserAuth<_Auth> {
	gitlabUser: GitlabUser;
	gitlabTokens: GitlabTokens;
}
```

| properties     | type                            | description       |
| -------------- | ------------------------------- | ----------------- |
| `gitlabUser`   | [`GitlabUser`](#gitlabuser)     | Gitlab user       |
| `gitlabTokens` | [`GitlabTokens`](#gitlabtokens) | Access tokens etc |

##### Generics

| name    | extends                                    |
| ------- | ------------------------------------------ |
| `_Auth` | [`Auth`](/reference/lucia/interfaces/auth) |
