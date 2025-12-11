
// this file is generated — do not edit it


declare module "svelte/elements" {
	export interface HTMLAttributes<T> {
		'data-sveltekit-keepfocus'?: true | '' | 'off' | undefined | null;
		'data-sveltekit-noscroll'?: true | '' | 'off' | undefined | null;
		'data-sveltekit-preload-code'?:
			| true
			| ''
			| 'eager'
			| 'viewport'
			| 'hover'
			| 'tap'
			| 'off'
			| undefined
			| null;
		'data-sveltekit-preload-data'?: true | '' | 'hover' | 'tap' | 'off' | undefined | null;
		'data-sveltekit-reload'?: true | '' | 'off' | undefined | null;
		'data-sveltekit-replacestate'?: true | '' | 'off' | undefined | null;
	}
}

export {};


declare module "$app/types" {
	export interface AppTypes {
		RouteId(): "/" | "/applications" | "/audit" | "/login" | "/scopes" | "/settings" | "/users";
		RouteParams(): {
			
		};
		LayoutParams(): {
			"/": Record<string, never>;
			"/applications": Record<string, never>;
			"/audit": Record<string, never>;
			"/login": Record<string, never>;
			"/scopes": Record<string, never>;
			"/settings": Record<string, never>;
			"/users": Record<string, never>
		};
		Pathname(): "/" | "/applications" | "/applications/" | "/audit" | "/audit/" | "/login" | "/login/" | "/scopes" | "/scopes/" | "/settings" | "/settings/" | "/users" | "/users/";
		ResolvedPathname(): `${"" | `/${string}`}${ReturnType<AppTypes['Pathname']>}`;
		Asset(): string & {};
	}
}