<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

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
                return $next($request);
            } else {
                return response()->json(['message' => 'Unauthorized'], 461);
            }
        } else {
            return response()->json(['message' => 'Unauthorized'], 461);
        }
    }
}
