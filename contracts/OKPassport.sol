// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "erc721a/contracts/ERC721A.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/common/ERC2981.sol";
import "operator-filter-registry/src/UpdatableOperatorFilterer.sol";

contract OKPassport is
    Ownable,
    UpdatableOperatorFilterer,
    ERC2981,
    ERC721A,
    ReentrancyGuard
{
    uint256 public maxSupply = 210;

    error MaxSupplyExceeded();
    error AirdropParamsError();
    error AddSupplyParamsError();
    error IsNoOwner();
    error TokenIsLocked(uint256 tokenId);
    error TokenIsUnlocked(uint256 tokenId);
    error LockQueryForNonexistentToken();

    event TokenLocked(uint256 indexed tokenId);
    event TokenUnlocked(uint256 indexed tokenId);
    event AddSupply(uint256 preSupply, uint256 addQuantity);
    event AipDropEvent(
        address[] accounts,
        uint256[] quantitys,
        uint256 startTokenId
    );
    event Burn(uint256 indexed burnToken);

    string private _uri;
    mapping(uint256 => bool) private _lockTokens; //token => isLooked

    constructor(
        string memory baseURI,
        string memory name,
        string memory symbol,
        address filterRegistry,
        address subscribeRegistry
    )
        ERC721A(name, symbol)
        UpdatableOperatorFilterer(address(0), address(0), false)
    {
        _uri = baseURI;
        _setDefaultRoyalty(msg.sender, 1000);
        operatorFilterRegistry = IOperatorFilterRegistry(filterRegistry);
        if (address(0) != filterRegistry) {
            operatorFilterRegistry.register(address(this));
            if (address(0) != subscribeRegistry) {
                operatorFilterRegistry.subscribe(
                    address(this),
                    subscribeRegistry
                );
            }
        }
    }

    function airdrop(
        address[] calldata accounts,
        uint256[] calldata quantitys
    ) public onlyOwner nonReentrant {
        uint256 length = accounts.length;
        if (length == 0 || length != quantitys.length) {
            revert AirdropParamsError();
        }
        uint256 startTokenId = _nextTokenId();
        for (uint256 i = 0; i < length; ) {
            address account = accounts[i];
            uint256 quantity = quantitys[i];
            if (totalSupply() + quantity > maxSupply) {
                revert MaxSupplyExceeded();
            }
            _mint(account, quantity);
            unchecked {
                i += 1;
            }
        }
        emit AipDropEvent(accounts, quantitys, startTokenId);
    }

    function tokenURI(
        uint256 tokenId
    ) public view virtual override returns (string memory) {
        if (!_exists(tokenId)) revert URIQueryForNonexistentToken();

        string memory baseURI = _baseURI();
        return
            bytes(baseURI).length != 0
                ? string(abi.encodePacked(baseURI, _toString(tokenId), ".json"))
                : "";
    }

    function setBaseURI(string calldata baseURI_) external onlyOwner {
        _uri = baseURI_;
    }

    function addSupply(uint256 quantity) external onlyOwner {
        if (quantity <= 0) {
            revert AddSupplyParamsError();
        }
        emit AddSupply(maxSupply, quantity);
        maxSupply = maxSupply + quantity;
    }

    function totalSupply() public view override returns (uint256) {
        unchecked {
            return _nextTokenId() - _startTokenId();
        }
    }

    function burn(uint256 tokenId) external onlyTokenOwner(tokenId) {
        if (_lockTokens[tokenId]) {
            revert TokenIsLocked(tokenId);
        }
        _burn(tokenId);
        emit Burn(tokenId);
    }

    function owner()
        public
        view
        virtual
        override(Ownable, UpdatableOperatorFilterer)
        returns (address)
    {
        return Ownable.owner();
    }

    function setRoyaltyInfo(
        address receiver,
        uint96 feeBasisPoints
    ) external onlyOwner {
        _setDefaultRoyalty(receiver, feeBasisPoints);
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC721A, ERC2981) returns (bool) {
        return
            ERC721A.supportsInterface(interfaceId) ||
            ERC2981.supportsInterface(interfaceId) ||
            super.supportsInterface(interfaceId);
    }

    function setApprovalForAll(
        address operator,
        bool approved
    ) public override(ERC721A) onlyAllowedOperatorApproval(operator) {
        super.setApprovalForAll(operator, approved);
    }

    function approve(
        address operator,
        uint256 tokenId
    ) public payable override(ERC721A) onlyAllowedOperatorApproval(operator) {
        super.approve(operator, tokenId);
    }

    function batchTransferFrom(
        address from,
        address to,
        uint256[] calldata tokens
    ) public payable onlyAllowedOperator(from) {
        for (uint256 index = 0; index < tokens.length; index++) {
            super.transferFrom(from, to, tokens[index]);
        }
    }

    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public payable override(ERC721A) onlyAllowedOperator(from) {
        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public payable override(ERC721A) onlyAllowedOperator(from) {
        super.safeTransferFrom(from, to, tokenId);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory data
    ) public payable override(ERC721A) onlyAllowedOperator(from) {
        super.safeTransferFrom(from, to, tokenId, data);
    }

    function lock(uint256[] calldata tokenIds) external {
        for (uint256 index = 0; index < tokenIds.length; index++) {
            uint256 tokenId = tokenIds[index];
            _checkTokenOwner(tokenId);
            if (_lockTokens[tokenId]) {
                revert TokenIsLocked(tokenId);
            }
            _lockTokens[tokenId] = true;
            emit TokenLocked(tokenId);
        }
    }

    function unlock(uint256[] calldata tokenIds) external {
        for (uint256 index = 0; index < tokenIds.length; index++) {
            uint256 tokenId = tokenIds[index];
            _checkTokenOwner(tokenId);
            if (!_lockTokens[tokenId]) {
                revert TokenIsUnlocked(tokenId);
            }
            delete _lockTokens[tokenId];
            emit TokenUnlocked(tokenId);
        }
    }

    function getLocked(uint256 tokenId) public view virtual returns (bool) {
        if (!_exists(tokenId)) {
            revert LockQueryForNonexistentToken();
        }
        return _lockTokens[tokenId];
    }

    function _beforeTokenTransfers(
        address from,
        address to,
        uint256 startTokenId,
        uint256 quantity
    ) internal virtual override {
        // if it is a Transfer or Burn, we always deal with one token, that is startTokenId
        if (from != address(0)) {
            if (_lockTokens[startTokenId]) {
                revert TokenIsLocked(startTokenId);
            }
        }
        super._beforeTokenTransfers(from, to, startTokenId, quantity);
    }

    function _afterTokenTransfers(
        address from,
        address to,
        uint256 startTokenId,
        uint256 quantity
    ) internal virtual override {
        // if it is a Transfer or Burn, we always deal with one token, that is startTokenId
        if (from != address(0)) {
            // clear locks
            delete _lockTokens[startTokenId];
        }
        super._afterTokenTransfers(from, to, startTokenId, quantity);
    }

    function _startTokenId() internal pure override(ERC721A) returns (uint256) {
        return 1;
    }

    function _baseURI()
        internal
        view
        override(ERC721A)
        returns (string memory)
    {
        return _uri;
    }

    modifier onlyTokenOwner(uint256 tokenId) virtual {
        address tokenOwner = ownerOf(tokenId);
        if (msg.sender != tokenOwner) {
            revert IsNoOwner();
        }
        _;
    }

    function _checkTokenOwner(uint256 tokenId) internal view {
        address tokenOwner = ownerOf(tokenId);
        if (msg.sender != tokenOwner) {
            revert IsNoOwner();
        }
    }
}
