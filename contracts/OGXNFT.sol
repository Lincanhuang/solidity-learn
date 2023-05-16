// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "erc721a/contracts/ERC721A.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/token/common/ERC2981.sol";
import "operator-filter-registry/src/UpdatableOperatorFilterer.sol";

contract OGXNFT is
Ownable,
UpdatableOperatorFilterer,
ERC2981,
ERC721A,
ReentrancyGuard
{
    struct Season {
        uint256 price;
        uint256 sellNum;
        uint256 start_time;
        uint256 end_time;
    }

    struct Whitelist {
        uint256 season;
        bytes32 merkleRoot;
    }

    using Strings for uint256;

    uint256 public constant MAX_SUPPLY = 10000;
    bool public allowBuy = true;
    uint256 public buyLimit = 2;

    uint256[] private seasonList;
    string private _hiddenMetadataURI;
    mapping(uint256 => string) public seasonUriMap;
    mapping(uint256 => Whitelist) public seasonWhitelist; // season => WhitelistSeason

    mapping(uint256 => uint256) private _tokenSeasonMap; // tokenId => season
    mapping(uint256 => mapping(uint256 => Season)) private _ogxSeasons; // seasonNum => type => FUNQSeason
    mapping(uint256 => bool) private _lockTokens; //token => isLooked

    event TokenBorned(
        address indexed owner,
        uint256 startTokenId,
        uint256 quantity,
        uint256 season
    );
    event AddSeasonEvolved(
        uint256 indexed season,
        uint256 indexed type_,
        uint256 sellNum,
        uint256 start_time,
        uint256 end_time
    );
    event UpdateSeasonEvolved(
        uint256 indexed season,
        uint256 indexed type_,
        uint256 end_time
    );
    event WhitelistRetire(uint256 indexed season);
    event AddToWhitelistEven(uint256 indexed season, bytes32 merkleRoot);
    event SeasonsRetire(uint256 indexed season, uint256 indexed type_);
    event TokenLocked(uint256 indexed tokenId);
    event TokenUnlocked(uint256 indexed tokenId);
    event OpenSeason(uint256 indexed season, string baseURI);

    error IsNoOwner();
    error SeasonURINotEmpty(uint256 seasonNum);
    error TokenIsLocked(uint256 tokenId);
    error TokenIsUnlocked(uint256 tokenId);
    error LockQueryForNonexistentToken();

    constructor(
        string memory hiddenMetadataURI,
        string memory name,
        string memory symbol,
        address filterRegistry,
        address subscribeRegistry
    )
    ERC721A(name, symbol)
    UpdatableOperatorFilterer(address(0), address(0), false)
    {
        _hiddenMetadataURI = hiddenMetadataURI;
        _initRetainSeason();
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
        seasonList.push(1);
        seasonList.push(2);
    }

    function addSeason(
        uint256 season,
        uint256 type_,
        uint256 price,
        uint256 sellNum,
        uint256 start_time,
        uint256 end_time
    ) external onlyOwner {
        require(season > 2, "season invalid");
        require(start_time > 0, "start time invalid");
        require((end_time > start_time), "end time invalid 1");
        require(sellNum > 0, "sell num invalid");
        Season storage ogxSeason = _ogxSeasons[season][type_];
        ogxSeason.price = price;
        ogxSeason.sellNum = sellNum;
        ogxSeason.start_time = start_time;
        ogxSeason.end_time = end_time;

        seasonList.push(season);

        emit AddSeasonEvolved(season, type_, sellNum, start_time, end_time);
    }

    function updateSeason(
        uint256 season,
        uint256 type_,
        uint256 end_time
    ) external onlyOwner {
        require(season > 2, "season invalid");
        Season storage ogxSeason = _ogxSeasons[season][type_];
        require(ogxSeason.start_time > 0, "season not exist");
        require(
            (end_time > ogxSeason.start_time),
            "end_time must over start_time"
        );
        ogxSeason.end_time = end_time;
        emit UpdateSeasonEvolved(season, type_, end_time);
    }

    function retireRemaining(uint256 season, uint256 type_) external onlyOwner {
        require(season > 2, "season invalid");
        delete (_ogxSeasons[season][type_]);
        for (uint i = 2; i < seasonList.length; i++) {
            if (season == seasonList[i]) {
                delete seasonList[i];
                break;
            }
        }
        emit SeasonsRetire(season, type_);
    }

    // Function to set the merkle root
    function addToWhitelist(
        uint256 season,
        bytes32 newMerkleRoot
    ) external onlyOwner {
        seasonWhitelist[season].season = season;
        seasonWhitelist[season].merkleRoot = newMerkleRoot;
        emit AddToWhitelistEven(season, newMerkleRoot);
    }

    function retireWhitelist(uint256 season) external onlyOwner {
        delete (seasonWhitelist[season]);
        emit WhitelistRetire(season);
    }

    function buyBox(
        uint256 season,
        uint256 type_,
        uint256 num,
        bytes32[] calldata merkleProof
    ) external payable {
        require(allowBuy, "buy disabled");
        require(season > 2, "season invalid");
        require(num > 0, "number invalid");
        require(_nextTokenId() > 6, "tokenId not up");
        require(totalSupply() + num <= MAX_SUPPLY, "over max supply");
        Season storage ogxSeason = _ogxSeasons[season][type_];
        require(
            (ogxSeason.start_time <= block.timestamp) &&
            (ogxSeason.end_time >= block.timestamp),
            "not in the sale period"
        );
        require(ogxSeason.sellNum > 0, "sold out");
        require(ogxSeason.sellNum >= num, "not enough left");
        require(ogxSeason.price * num <= msg.value, "ether invalid");
        address sender = _msgSender();
        if (type_ == 1) {
            Whitelist storage _whitelistSeason = seasonWhitelist[season];
            require(
                _whitelistSeason.season != 0,
                "whitelist season nonexistent"
            );
            bytes32 leaf = keccak256(abi.encodePacked(sender));
            require(
                MerkleProof.verify(
                    merkleProof,
                    _whitelistSeason.merkleRoot,
                    leaf
                ),
                "not in the whitelist."
            );
        }
        // Check max box per user
        uint256 totalBoxes = balanceOf(sender) + num;
        require(buyLimit < totalBoxes, "reach the limit");
        // Transfer payment
        refundIfOver(ogxSeason.price * num);

        uint256 startTokenId = _nextTokenId();
        _mint(sender, num);
        ogxSeason.sellNum = ogxSeason.sellNum - num;
        _bornOGX(startTokenId, season);
        emit TokenBorned(sender, startTokenId, num, season);
    }

    function treasuryWithdraw(
        address address_,
        uint256 value
    ) external onlyOwner nonReentrant {
        require(address(this).balance >= value, "withdraw too much");
        if (address(this).balance >= value) {
            payable(address_).transfer(value);
        }
    }

    function mintNFTToTeamMember(uint256 num, address to) external onlyOwner {
        require(allowBuy, "buy disabled");
        require(_nextTokenId() > 6, "tokenId not up");
        require(totalSupply() + num <= MAX_SUPPLY, "over max supply");
        // Add user bought boxes
        uint256 startTokenId = _nextTokenId();
        _mint(to, num);
        _bornOGX(startTokenId, 2);
        emit TokenBorned(to, startTokenId, num, 2);
    }

    function mintExtraNFT(uint256 num, address to) external onlyOwner {
        require(allowBuy, "buy disabled");
        require(totalSupply() + num <= MAX_SUPPLY, "over max supply");
        Season storage ogxSeason = _ogxSeasons[1][0];
        require(ogxSeason.sellNum > 0, "sold out");
        require(ogxSeason.sellNum >= num, "not enough left");
        uint256 startTokenId = _nextTokenId();
        _mint(to, num);
        ogxSeason.sellNum = ogxSeason.sellNum - num;
        _bornOGX(startTokenId, 1);
        emit TokenBorned(to, startTokenId, num, 1);
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

    function tokenURI(
        uint256 tokenId
    ) public view override returns (string memory) {
        if (tokenId < _startTokenId() || tokenId >= _nextTokenId()) {
            return string(abi.encodePacked(_hiddenMetadataURI, "0.json"));
        } else {
            string memory uri = _findBaseURI(tokenId);
            if (bytes(uri).length == 0) {
                return string(abi.encodePacked(_hiddenMetadataURI, "0.json"));
            } else {
                return
                string(abi.encodePacked(uri, tokenId.toString(), ".json"));
            }
        }
    }

    function openSeason(
        uint256 seasonNum,
        string calldata baseUri
    ) external onlyOwner {
        if (bytes(seasonUriMap[seasonNum]).length > 0) {
            revert SeasonURINotEmpty(seasonNum);
        }
        seasonUriMap[seasonNum] = baseUri;
        emit OpenSeason(seasonNum, baseUri);
    }

    function setBaseURI(string calldata baseUri) external onlyOwner {
        require(bytes(baseUri).length > 0, "baseUri is empty");
        for (uint i = 0; i < seasonList.length; i++) {
            uint256 seasonNum = seasonList[i];
            if (seasonNum > 0) {
                seasonUriMap[seasonNum] = baseUri;
                emit OpenSeason(seasonNum, baseUri);
            }
        }
    }

    function setHiddenMetadataURI(
        string memory hiddenMetadataURI
    ) external onlyOwner {
        _hiddenMetadataURI = hiddenMetadataURI;
    }

    function setAllowBuy(bool allowBuy_) external onlyOwner {
        allowBuy = allowBuy_;
    }

    function setBuyLimit(uint256 buyLimit_) external onlyOwner {
        buyLimit = buyLimit_;
    }

    function getSeason(
        uint256 season,
        uint256 type_
    ) external view returns (uint256, uint256, uint256, bool) {
        Season storage ogxSeason = _ogxSeasons[season][type_];
        bool soldOut = (ogxSeason.sellNum == 0);
        return (
            ogxSeason.price,
            ogxSeason.start_time,
            ogxSeason.end_time,
            soldOut
        );
    }

    function refundIfOver(uint256 price) private {
        require(msg.value >= price, "need more eth");
        if (msg.value > price) {
            payable(msg.sender).transfer(msg.value - price);
        }
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

    // ========= OPERATOR FILTERER OVERRIDES =========

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

    function owner()
    public
    view
    virtual
    override(Ownable, UpdatableOperatorFilterer)
    returns (address)
    {
        return Ownable.owner();
    }

    // teammeber season is alway 0 and type is always 0
    function _initRetainSeason() private {
        Season storage extraSeason = _ogxSeasons[1][0];
        extraSeason.sellNum = 6;
    }

    function _startTokenId() internal view virtual override returns (uint256) {
        return 1;
    }

    function _bornOGX(uint256 startTokenId, uint256 season) private {
        _tokenSeasonMap[startTokenId] = season;
    }

    function _findBaseURI(
        uint256 tokenId
    ) internal view returns (string memory) {
        string memory foundUri;
        if (tokenId < _nextTokenId()) {
            uint256 startTokenId = _startTokenId();
            for (; tokenId >= startTokenId; tokenId--) {
                uint256 seasonNum = _tokenSeasonMap[tokenId];
                if (seasonNum > 0) {
                    foundUri = seasonUriMap[seasonNum];
                    return foundUri;
                }
            }
        }
        return foundUri;
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

    function _checkTokenOwner(uint256 tokenId) internal view {
        address tokenOwner = ownerOf(tokenId);
        if (msg.sender != tokenOwner) {
            revert IsNoOwner();
        }
    }
}
