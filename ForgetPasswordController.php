<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ForgetPasswordController extends Controller
{
    
    function sendForgotPasswordOtp(Request $request)

    {
        $validator = Validator::make($request->all(), [
            'email' => 'required',
    
        ]);
        if ($validator->fails()) {
            return response()->json([
                'status' => 401,
                'message' => 'validation error',
                'errors' => $validator->errors()
            ], 401);
        }
    
        $email = $request->input('email');
        $users = User::where('email', $email)->first();
    
        $otp = mt_rand(100000, 999999);
        $expirationTime = Carbon::now()->addMinutes(15);
        $hashedOtp = Hash::make($otp);
        DB::table('otpdata')->insert([
            'email' => $email,
            'otp' =>  $hashedOtp,
            'expires_at' => $expirationTime,
        ]);
        $to = $email;
        $subject = 'OTP Verification';
        $message = 'The OTP to reset your password is: ' . $otp;
    
        $data = [
            'user_name' => $users->full_name,
            'otp_code' => $otp,
        ];
        // Mail::raw($message, function ($email) use ($to, $subject) {
        //     $email->to($to)
        //         ->subject($subject);
        // });
        Mail::send('Email.password_verification', $data, function ($message) use ($to, $subject) {
            $message->to($to)
                ->subject($subject);
        });
        // dd(session('otp'));
        return response()->json([
            'status' => 200,
    
            'message' => 'OTP code sent to your email address.',
        ], 200);
    }
    
    public function validateOtp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'otp' => 'required',
    
        ]);
        if ($validator->fails()) {
            return response()->json([
                'status' => 401,
                'message' => 'validation error',
                'errors' => $validator->errors()
            ], 401);
        }
    
    
        $user = User::where('email', $request->email)->first();
        if ($user) {
    
    
            // Fetch the OTP from the database based on the email
            $providedOtp = $request->input('otp');
            $dbOtp = DB::table('otpdata')
                ->where('email', $request->email)
                ->first();
    
            if (!$dbOtp) {
                return response()->json([
                    'status' => 400,
                    'message' => 'Invalid key.',
                ], 400);
            }
    
            if (!Hash::check($providedOtp, $dbOtp->otp)) {
                return response()->json([
                    'status' => 401,
                    'message' => 'Invalid OTP code.',
                ], 401);
            }
    
            if (Carbon::now()->gt($dbOtp->expires_at)) {
                DB::table('otpdata')
                    ->where('email', $request->email)
                    ->delete();
                return response()->json([
                    'status' => 401,
                    'message' => 'OTP code has expired. Please request a new one.',
                ], 401);
            }
            DB::table('otpdata')
                ->where('email', $request->email)
                ->delete();
            auth()->login($user);
            // dd("welcome");
            return response()->json([
                'status' => 200,
                'message' => 'OTP verified successfully. Proceed with password reset.',
                'accessToken' => JWTAuth::fromUser(auth()->user()),
            ], 200);
        }
    }
    public function reset(Request $request): JsonResponse
    {
        try {
            $validator = Validator::make($request->all(), [
                'newPassword' => 'required',
                'confirmPassword' => 'required|same:newPassword',
            ]);
            if ($validator->fails()) {
                return response()->json([
                    'status' => 401,
                    'message' => 'validation error',
                    'errors' => $validator->errors()
                ], 401);
            }
            $token = $request->header('Authorization');
    
            if (!$token) {
                return response()->json([
                    'status' => 401,
                    'message' => 'token not provided',
                ], 401);
            }
    
            $token = str_replace('Bearer ', '', $token);
    
            $tokenParts = explode('.', $token);
            $payload = base64_decode($tokenParts[1]);
            $decodedPayload = json_decode($payload, true);
            $user_id = $decodedPayload['sub'];
            $newPassword = $request->input('newPassword');
    
            $user = User::where('id', $user_id)->first();
            if ($user) {
    
                $user->password = Hash::make($newPassword);
                $user->save();
                $users = User::with(
                    'sellers.users.locations',
                    'sellers.users.zones',
                    'sellers.users.images',
                    'sellers.users.regions.zones',
                    'sellers.businesses',
                    'sellers.levels'
                )->where('id', $user_id)->get();
                return response()->json([
                    'status' => 200,
                    'message' => 'password rest successfully',
                    'user' => $users,
                ], 200);
            }
            return response()->json([
                'status' => 404,
                'message' => 'user not found',
            ], 404);
        } catch (\Throwable $th) {
            return response()->json([
    
                'message' => $th->getMessage()
            ], 500);
        }
    }
    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        //
    }
}
