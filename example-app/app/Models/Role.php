<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;


class Role extends Model
{
    use HasFactory;
    const ROLE_SERVICE_ADMIN = 1;
    const ROLE_COMPANY_OWNER = 2;
    const ROLE_COMPANY_ADMIN = 3;
    const ROLE_COMPANY_USER = 4;
}
