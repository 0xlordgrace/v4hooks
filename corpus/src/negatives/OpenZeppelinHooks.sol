// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// Pulls OpenZeppelin uniswap-hooks v1.2.1 concrete examples into the build so the
// scanner sees them. These are the clean-negative half of the benchmark.
import {BaseAsyncSwapMock} from "@openzeppelin/uniswap-hooks/mocks/base/BaseAsyncSwapMock.sol";
import {BaseCustomAccountingMock} from "@openzeppelin/uniswap-hooks/mocks/base/BaseCustomAccountingMock.sol";
import {BaseCustomCurveMock} from "@openzeppelin/uniswap-hooks/mocks/base/BaseCustomCurveMock.sol";
import {BaseDynamicAfterFeeMock} from "@openzeppelin/uniswap-hooks/mocks/fee/BaseDynamicAfterFeeMock.sol";
import {BaseDynamicFeeMock} from "@openzeppelin/uniswap-hooks/mocks/fee/BaseDynamicFeeMock.sol";
import {BaseHookFeeMock} from "@openzeppelin/uniswap-hooks/mocks/fee/BaseHookFeeMock.sol";
import {BaseOverrideFeeMock} from "@openzeppelin/uniswap-hooks/mocks/fee/BaseOverrideFeeMock.sol";
import {AntiSandwichMock} from "@openzeppelin/uniswap-hooks/mocks/general/AntiSandwichMock.sol";
import {LimitOrderHookMock} from "@openzeppelin/uniswap-hooks/mocks/general/LimitOrderHookMock.sol";
import {LiquidityPenaltyHookMock} from "@openzeppelin/uniswap-hooks/mocks/general/LiquidityPenaltyHookMock.sol";
import {ReHypothecationERC4626Mock} from "@openzeppelin/uniswap-hooks/mocks/general/ReHypothecationERC4626Mock.sol";
import {ReHypothecationNativeMock} from "@openzeppelin/uniswap-hooks/mocks/general/ReHypothecationNativeMock.sol";
