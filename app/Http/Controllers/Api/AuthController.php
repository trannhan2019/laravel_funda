<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'name' => 'required|max:191',
                'email' => 'required|email|max:191|unique:users,email',
                'password' => 'required|min:8',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'validation_errors' => $validator->messages(),
                ]);
            } else {
                $user = User::create([
                    'name' => $request->name,
                    'email' => $request->email,
                    'password' => Hash::make($request->password),
                ]);

                $token = $user->createToken($user->email . '_Token')->plainTextToken;
                return response()->json([
                    'status' => 200,
                    'username' => $user->name,
                    'token' => $token,
                    'message' => 'Register Successfully'
                ]);
            }
        }catch (Exception $error){
            return response()->json([
                'status' => 500,
                'message' => 'Error in Registration',
                'error' => $error,
            ]);
        }
    }

    public function login(Request $request){
        try {
            $validator = Validator::make($request->all(),[
                'email' => 'required|email',
                'password' => 'required',
            ]);

            if ($validator->fails()){
                return response()->json([
                    'validation_errors' => $validator->messages(),
                ]);
            }else{
                $user = User::where('email', $request->email)->first();

                if (! $user || ! Hash::check($request->password, $user->password)) {
                    return response()->json([
                        'status' => 401,
                        'message' => 'Invalid Credentials',
                    ]);
                }else{
                    $token = $user->createToken($user->email . '_Token')->plainTextToken;
                    return response()->json([
                        'status' => 200,
                        'username' => $user->name,
                        'token' => $token,
                        'message' => 'Login Successfully'
                    ]);
                }
            }
        }catch(Exception $error){
            return response()->json([
                'status_code' => 500,
                'message' => 'Error in Login',
                'error' => $error,
            ]);
        }

    }

    public function logout(){
        try {
            auth()->user()->tokens()->delete();
            return response()->json([
                'status'=>200,
                'message'=>'Logged Out Successfully',
            ]);
        }catch(Exception $error){
            return response()->json([
                'status_code' => 500,
                'message' => 'Error in Logout',
                'error' => $error,
            ]);
        }
    }
}
