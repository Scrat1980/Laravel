<?php

namespace App\Http\Controllers\API;

use App\Models\Role;
use Exception;
use Illuminate\Http\Request;
use App\Http\Controllers\API\BaseController as BaseController;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Validator;
use Illuminate\Http\JsonResponse;

class RegisterController extends BaseController
{
    /**
     * Register api
     *
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if($validator->fails()){
            return $this->sendError('Validation Error.', $validator->errors());
        }

        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);
        $success['token'] =  $user->createToken('MyApp')->plainTextToken;
        $success['name'] =  $user->name;

        return $this->sendResponse($success, 'User register successfully.');
    }

    /**
     * Login api
     *
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request): JsonResponse
    {
        try {
           $auth = Auth::attempt([
               'email' => $request->email,
               'password' => $request->password,
               'active' => 1,
           ]);
        } catch (Exception $exception) {
            return response()->json([], 500);
        }

        if($auth){
            $user = Auth::user();

            $roles = DB::table('users_companies_roles')
//                ->join('roles', 'role_id', '=', 'roles.id')
//                ->join('companies', 'company_id', '=', 'companies.id')
                ->where(['user_id' => $user->getAuthIdentifier()])
                ->groupBy('user_id', 'company_id')
                ->select([
                    'users_companies_roles.company_id',
                    DB::raw('GROUP_CONCAT(users_companies_roles.role_id) as roles'),
                ])
                ->get()
                ->toArray()
            ;

            $token = $user->createToken(
                'MyApp',
                $roles,
                now()->addDay()
            )
                ->plainTextToken
            ;

            return response()->json([
                "jwt-token" => $token,
                "roles" => $roles
            ], 200);
        }
        else{
            return response()->json([], 500);
        }
    }

    public function inviteCompany(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'companyName' => 'required|unique:companies,name',
        ]);

        if ($validator->fails())
        {
            return response()->json([], 500);
        }

        DB::beginTransaction();
        $companyId = DB::table('companies')->insertGetId([
            'name' => $request->get('companyName')
        ]);

        $user = User::where('email', $request->get('email'))->first();
        if (!$user)
        {
            $user = new User([
                'email' => $request->get('email'),
                'password' => 1
            ]);
            $user->save();
        }

        //As we have just created the company, it does not have a row in
        // u_c_r table.
        DB::table('users_companies_roles')
            ->insert([
                'user_id' => $user->id,
                'company_id' => $companyId,
                'role_id' => Role::ROLE_COMPANY_OWNER,
            ])
        ;

        DB::table('invitations')
            ->insert([
                'email' => $request->get('email'),
                'token' => $user->createToken(
                    'MyApp',
                    [Role::ROLE_COMPANY_OWNER],
                    now()->addDay()
                )->plainTextToken,
        ]);
        DB::commit();

        return response()->json([], 200);
    }

    public function inviteUser(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|unique:users,email',
            'roleIds' => 'required|array',
            'roleIds.*' => 'in:3,4',
        ]);

        if ($validator->fails())
        {
            return response()->json([], 500);
        }

        $user = User::where('email', $request->get('email'))->first();
        if (!$user)
        {

        } else {

        }

        return response()->json([], 200);
    }

    public function activate(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'name' => 'required',
            'surname' => 'required',
            'password' => 'required',
            'token' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json([], 500);
        }

        $user = User::where('email', $request->get('email'))->first();
        if ($user && !$user->active)
        {
            $user->active = 1;
            return response()->json([], 200);
        }

    }
}
