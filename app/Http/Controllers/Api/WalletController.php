<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Wallet;
use Illuminate\Http\Request;

/**
 * @OA\Schema(
 *     schema="Wallet",
 *     type="object",
 *     @OA\Property(property="id", type="integer", example=1),
 *     @OA\Property(property="user_id", type="integer", example=10),
 *     @OA\Property(property="balance", type="number", format="float", example=500.00),
 *     @OA\Property(property="currency", type="string", example="PHP")
 * )
 *
 * @OA\Schema(
 *     schema="WalletTransaction",
 *     type="object",
 *     @OA\Property(property="id", type="integer", example=1),
 *     @OA\Property(property="wallet_id", type="integer", example=1),
 *     @OA\Property(property="type", type="string", example="credit"),
 *     @OA\Property(property="source_type", type="string", example="order"),
 *     @OA\Property(property="source_id", type="integer", example=123),
 *     @OA\Property(property="amount", type="number", format="float", example=250.00),
 *     @OA\Property(property="balance_before", type="number", format="float", example=100.00),
 *     @OA\Property(property="balance_after", type="number", format="float", example=350.00),
 *     @OA\Property(property="description", type="string", example="Earnings from completed trip")
 * )
 */
class WalletController extends Controller
{
    /**
     * Authorization gate for wallet access.
     * Owner can access own wallet; admin can access any wallet.
     */
    protected function authorizeWalletAccess(Request $request, int $userId): void
    {
        $auth = $request->user();

        // If no auth user (should not happen if route is protected)
        if (! $auth) {
            abort(401, 'Unauthenticated');
        }

        // Allow owner or admin only
        if ((int) $auth->id !== (int) $userId && ! $auth->isAdmin()) {
            abort(403, 'Forbidden');
        }
    }

    /**
     * Get wallet by user ID (secured).
     *
     * @OA\Get(
     *     path="/api/v1/wallets/{user_id}",
     *     summary="Get wallet balance for a user (owner/admin only)",
     *     tags={"Wallets"},
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="user_id",
     *         in="path",
     *         required=true,
     *         description="User ID",
     *         @OA\Schema(type="integer", example=10)
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Wallet details",
     *         @OA\JsonContent(ref="#/components/schemas/Wallet")
     *     ),
     *     @OA\Response(response=401, description="Unauthenticated"),
     *     @OA\Response(response=403, description="Forbidden"),
     *     @OA\Response(response=404, description="Not found")
     * )
     */
    public function showByUser(Request $request, int $userId)
    {
        $this->authorizeWalletAccess($request, $userId);

        $wallet = Wallet::where('user_id', $userId)->firstOrFail();

        return response()->json($wallet);
    }

    /**
     * List wallet transactions for a user (secured).
     *
     * @OA\Get(
     *     path="/api/v1/wallets/{user_id}/transactions",
     *     summary="List wallet transactions for a user (owner/admin only)",
     *     tags={"Wallets"},
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="user_id",
     *         in="path",
     *         required=true,
     *         description="User ID",
     *         @OA\Schema(type="integer", example=10)
     *     ),
     *     @OA\Parameter(
     *         name="type",
     *         in="query",
     *         required=false,
     *         description="Filter by transaction type (credit/debit)",
     *         @OA\Schema(type="string", example="credit")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="List of wallet transactions",
     *         @OA\JsonContent(
     *             type="array",
     *             @OA\Items(ref="#/components/schemas/WalletTransaction")
     *         )
     *     ),
     *     @OA\Response(response=401, description="Unauthenticated"),
     *     @OA\Response(response=403, description="Forbidden"),
     *     @OA\Response(response=404, description="Not found")
     * )
     */
    public function transactionsByUser(Request $request, int $userId)
    {
        $this->authorizeWalletAccess($request, $userId);

        $type = $request->query('type');
        if ($type && ! in_array($type, ['credit', 'debit'], true)) {
            return response()->json([
                'message' => 'Invalid type. Allowed: credit, debit'
            ], 422);
        }

        $wallet = Wallet::where('user_id', $userId)
            ->with(['transactions' => function ($q) use ($type) {
                if ($type) {
                    $q->where('type', $type);
                }
                $q->orderByDesc('id');
            }])
            ->firstOrFail();

        return response()->json($wallet->transactions);
    }

    /**
     * Optional: My wallet endpoint (no user_id in URL).
     * Create routes:
     *   GET /api/v1/me/wallet
     *   GET /api/v1/me/wallet/transactions
     */
    public function myWallet(Request $request)
    {
        return $this->showByUser($request, (int) $request->user()->id);
    }

    public function myTransactions(Request $request)
    {
        return $this->transactionsByUser($request, (int) $request->user()->id);
    }
}
