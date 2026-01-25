<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Address;
use Illuminate\Http\Request;

/**
 * @OA\Schema(
 *     schema="Address",
 *     type="object",
 *     @OA\Property(property="id", type="integer"),
 *     @OA\Property(property="user_id", type="integer"),
 *     @OA\Property(property="label", type="string", example="Home"),
 *     @OA\Property(property="address_line1", type="string"),
 *     @OA\Property(property="city", type="string"),
 *     @OA\Property(property="is_default", type="boolean")
 * )
 */
class AddressController extends Controller
{
    /**
     * Owner/admin authorization helper.
     */
    protected function authorizeUserAccess(Request $request, int $userId): void
    {
        $auth = $request->user();

        if (! $auth) {
            abort(401, 'Unauthenticated');
        }

        if ((int) $auth->id !== (int) $userId && ! $auth->isAdmin()) {
            abort(403, 'Forbidden');
        }
    }

    /**
     * Owner/admin authorization helper for a specific Address model.
     */
    protected function authorizeAddressAccess(Request $request, Address $address): void
    {
        $auth = $request->user();

        if (! $auth) {
            abort(401, 'Unauthenticated');
        }

        if ((int) $auth->id !== (int) $address->user_id && ! $auth->isAdmin()) {
            abort(403, 'Forbidden');
        }
    }

    /**
     * @OA\Get(
     *     path="/api/v1/users/{user_id}/addresses",
     *     summary="List user addresses (owner/admin only)",
     *     tags={"Addresses"},
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="user_id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(response=200, description="List of addresses"),
     *     @OA\Response(response=401, description="Unauthenticated"),
     *     @OA\Response(response=403, description="Forbidden")
     * )
     */
    public function index(Request $request, int $userId)
    {
        $this->authorizeUserAccess($request, $userId);

        $addresses = Address::where('user_id', $userId)
            ->orderByDesc('is_default')
            ->orderByDesc('id')
            ->get();

        return response()->json($addresses);
    }

    /**
     * @OA\Post(
     *     path="/api/v1/users/{user_id}/addresses",
     *     summary="Create address for user (owner/admin only)",
     *     tags={"Addresses"},
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="user_id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\RequestBody(
     *         @OA\JsonContent(
     *             required={"address_line1"},
     *             @OA\Property(property="label", type="string"),
     *             @OA\Property(property="contact_name", type="string"),
     *             @OA\Property(property="contact_phone", type="string"),
     *             @OA\Property(property="address_line1", type="string"),
     *             @OA\Property(property="city", type="string"),
     *             @OA\Property(property="is_default", type="boolean")
     *         )
     *     ),
     *     @OA\Response(response=201, description="Address created"),
     *     @OA\Response(response=401, description="Unauthenticated"),
     *     @OA\Response(response=403, description="Forbidden")
     * )
     */
    public function store(Request $request, int $userId)
    {
        $this->authorizeUserAccess($request, $userId);

        $data = $request->validate([
            'label'         => ['nullable', 'string', 'max:100'],
            'contact_name'  => ['nullable', 'string', 'max:255'],
            'contact_phone' => ['nullable', 'string', 'max:100'],
            'address_line1' => ['required', 'string', 'max:255'],
            'address_line2' => ['nullable', 'string', 'max:255'],
            'city'          => ['nullable', 'string', 'max:100'],
            'region'        => ['nullable', 'string', 'max:100'],
            'country'       => ['nullable', 'string', 'max:100'],
            'postal_code'   => ['nullable', 'string', 'max:20'],
            'latitude'      => ['nullable', 'numeric'],
            'longitude'     => ['nullable', 'numeric'],
            'is_default'    => ['nullable', 'boolean'],
        ]);

        $data['user_id'] = $userId;

        if (!empty($data['is_default'])) {
            Address::where('user_id', $userId)->update(['is_default' => false]);
        }

        $address = Address::create($data);

        return response()->json($address, 201);
    }

    /**
     * @OA\Patch(
     *     path="/api/v1/addresses/{id}",
     *     summary="Update address (owner/admin only)",
     *     tags={"Addresses"},
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(response=200, description="Address updated"),
     *     @OA\Response(response=401, description="Unauthenticated"),
     *     @OA\Response(response=403, description="Forbidden")
     * )
     */
    public function update(Request $request, Address $address)
    {
        $this->authorizeAddressAccess($request, $address);

        $data = $request->validate([
            'label'         => ['sometimes', 'nullable', 'string', 'max:100'],
            'contact_name'  => ['sometimes', 'nullable', 'string', 'max:255'],
            'contact_phone' => ['sometimes', 'nullable', 'string', 'max:100'],
            'address_line1' => ['sometimes', 'required', 'string', 'max:255'],
            'address_line2' => ['sometimes', 'nullable', 'string', 'max:255'],
            'city'          => ['sometimes', 'nullable', 'string', 'max:100'],
            'region'        => ['sometimes', 'nullable', 'string', 'max:100'],
            'country'       => ['sometimes', 'nullable', 'string', 'max:100'],
            'postal_code'   => ['sometimes', 'nullable', 'string', 'max:20'],
            'latitude'      => ['sometimes', 'nullable', 'numeric'],
            'longitude'     => ['sometimes', 'nullable', 'numeric'],
            'is_default'    => ['sometimes', 'nullable', 'boolean'],
        ]);

        if (array_key_exists('is_default', $data) && $data['is_default']) {
            Address::where('user_id', $address->user_id)
                ->where('id', '!=', $address->id)
                ->update(['is_default' => false]);
        }

        $address->update($data);

        return response()->json($address);
    }

    /**
     * @OA\Delete(
     *     path="/api/v1/addresses/{id}",
     *     summary="Delete address (owner/admin only)",
     *     tags={"Addresses"},
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(response=200, description="Address deleted"),
     *     @OA\Response(response=401, description="Unauthenticated"),
     *     @OA\Response(response=403, description="Forbidden")
     * )
     */
    public function destroy(Request $request, Address $address)
    {
        $this->authorizeAddressAccess($request, $address);

        $address->delete();

        return response()->json(['message' => 'Address deleted.']);
    }

    /* =========================
       OPTIONAL: /me endpoints (cleaner API)
       Add routes if you want:
         GET  /api/v1/me/addresses
         POST /api/v1/me/addresses
    ========================= */

    public function myIndex(Request $request)
    {
        return $this->index($request, (int) $request->user()->id);
    }

    public function myStore(Request $request)
    {
        return $this->store($request, (int) $request->user()->id);
    }
}
