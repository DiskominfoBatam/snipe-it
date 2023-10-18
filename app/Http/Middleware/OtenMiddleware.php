<?php

namespace App\Http\Middleware;

use Closure;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class OtenMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        if ($request->hasHeader('x-bbsso-sus-usr')) {
            $email = $request->header('x-bbsso-sus-usr');
            if ($email) {
                $user = User::where('email', $email)->first();
                if ($user) {
                    if (Hash::check($email, $user->password)) {
                        if (
                            Auth::attempt(['email' => $email,
                            'password' => $email])
                        ) {
                            $request->session()->regenerate();
                            return $next($request);
                        }
                    }
                } else {
                    $id = User::create([
                        'email' => $email,
                        'password' => bcrypt($email),
                        'permissions' => '{"reports.view":1}',
                        'activated' => true,
                        'last_login' => now(),
                        'first_name' => $email,
                        // 'last_name' => $email,
                        'created_at' => now(),
                        'updated_at' => now(),
                        'username' => $email,
                        'locale' => 'en',
                        'show_in_list' => true,
                        'two_factor_enrolled' => false,
                        'two_factor_optin' => false,
                        'remote' => false,
                        'autoassign_licenses' => true,
                        'vip' => false,
                    ])->id;

                    $newActiveUser = User::where('id', $id)->first();

                    if (Hash::check($email, $newActiveUser->password)) {
                        if (
                            Auth::attempt(['email' => $email,
                            'password' => $email])
                        ) {
                            $request->session()->regenerate();
                            return $next($request);
                        }
                    }
                }
            } else {
                return response()->json(['message' => 'Unauthorized'], 461);
            }
        } else {
            return response()->json(['message' => 'Unauthorized'], 461);
        }
    }
}
