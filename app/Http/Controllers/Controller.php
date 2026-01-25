<?php

namespace App\Http\Controllers;

/**
 * @OA\Info(
 *     title="LeSGo API",
 *     version="1.0.0",
 *     description="Logistics & multi-service API documentation for LeSGo."
 * )
 *
 * @OA\SecurityScheme(
 *     securityScheme="sanctum",
 *     type="http",
 *     scheme="bearer",
 *     bearerFormat="JWT"
 * )
 */
abstract class Controller
{
    //
}
