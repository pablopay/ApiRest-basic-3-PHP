<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request){
    $validator = Validator::make($request->all(),[
            'name' => 'required|string|min:10|max:100',
            'role' => 'required|string|in:admin,user',
            'email'=> 'required|string|email|min:10|max:50|unique:users',
            'password' => 'required|string|min:5|max:30|confirmed',

        ]);
        if($validator->failed()) {
            return response()->json(['error' => $validator->errors()], 422);
         }
         User::create([
            'name'=> $request->get('name'),
            'email' => $request->get(key: 'email'),
            'role' => $request->get(key: 'role'),
            'password' => bcrypt($request->get(key: 'password')),
            ]);
    }
}
